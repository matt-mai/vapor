package attest

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/schema/contents"
)

// targets the package, and a reader matching against its SBOM has that same name.
func (input *VEXInput) packageProducts(name string) ([]product, error) {
	// The name has to be one the lock holds, so a claim cannot invent a package that
	// looks present in the image.
	products, err := input.product(name)
	if err != nil {
		return nil, err
	}
	if products != nil {
		return products, nil
	}
	return nil, fmt.Errorf("package %q is not locked on %s", name, input.Platform)
}

// product returns the one package URL a locked name resolves to, or nil when the lock
// does not hold that name.
func (input *VEXInput) product(name string) ([]product, error) {
	for position := range input.Packages {
		record := &input.Packages[position]
		if record.Platform == input.Platform && record.Name == name {
			return input.deb(record.Repository, record.Name, record.Version,
				record.Architecture, record.Source)
		}
	}
	for position := range input.Slices {
		record := &input.Slices[position]
		if record.Platform == input.Platform && record.Package == name {
			return input.deb(record.Repository, record.Package, record.Version,
				record.Architecture, record.Source)
		}
	}
	return nil, nil
}

func (input *VEXInput) artifactProducts(name string) ([]product, error) {
	for position := range input.Artifacts {
		record := &input.Artifacts[position]
		if record.Platform != input.Platform || record.Name != name {
			continue
		}
		if record.SBOM.Name == "" || record.SBOM.Version == "" {
			return nil, fmt.Errorf("artifact %q declares no name and version to identify it", name)
		}
		built, err := parseProduct(artifactURL(record.SBOM.Name, record.SBOM.Version))
		if err != nil {
			return nil, err
		}
		return []product{built}, nil
	}
	return nil, fmt.Errorf("artifact %q is not locked on %s", name, input.Platform)
}

// deb builds a package product from a locked record.
func (input *VEXInput) deb(repository, name, version, arch, upstream string) ([]product, error) {
	vendor, release := input.vendorOf(repository)
	built, err := parseProduct(packageURL(vendor, release, name, version, arch, upstream))
	if err != nil {
		return nil, err
	}
	return []product{built}, nil
}

// vendorOf returns the namespace and release a record is published under, which is the
// vendor's own for a repository that authenticates its own release identity.
func (input *VEXInput) vendorOf(repository string) (string, string) {
	for position := range input.Repositories {
		record := &input.Repositories[position]
		if record.Platform == input.Platform && record.ID == repository &&
			record.Identity == contents.RepositoryIdentityOwn {
			return record.Name, record.Suite
		}
	}
	return input.Distro, input.Release
}

// importProducts matches each product an imported statement names to the lock.
func (input *VEXInput) importProducts(statement *VEXStatement) ([]product, error) {
	known, err := input.knownProducts()
	if err != nil {
		return nil, err
	}
	resolved := make([]product, 0, len(statement.Products))
	for position := range statement.Products {
		named := statement.Products[position].purl()
		parsed, err := parseProduct(named)
		if err != nil {
			return nil, err
		}
		if err := checkEligible(&parsed, input.Platform, known); err != nil {
			return nil, err
		}
		matches := known.matching(&parsed)
		if len(matches) == 0 {
			return nil, fmt.Errorf("product %q is not in the lock for %s", named, input.Platform)
		}
		resolved = append(resolved, matches...)
	}
	return resolved, nil
}

// productSet is every product this platform's lock can supply.
type productSet []product

func (input *VEXInput) knownProducts() (productSet, error) {
	urls := input.lockProductURLs()
	found := make(productSet, 0, len(urls))
	for _, url := range urls {
		built, err := parseProduct(url)
		if err != nil {
			return nil, err
		}
		found = append(found, built)
	}
	return found, nil
}

// lockProductURLs renders every product this platform's lock names.
func (input *VEXInput) lockProductURLs() []string {
	urls := make([]string, 0, len(input.Packages)+len(input.Slices)+len(input.Artifacts))
	for position := range input.Packages {
		record := &input.Packages[position]
		if record.Platform == input.Platform {
			vendor, release := input.vendorOf(record.Repository)
			urls = append(urls, packageURL(vendor, release,
				record.Name, record.Version, record.Architecture, record.Source))
		}
	}
	for position := range input.Slices {
		record := &input.Slices[position]
		if record.Platform == input.Platform {
			vendor, release := input.vendorOf(record.Repository)
			urls = append(urls, packageURL(vendor, release,
				record.Package, record.Version, record.Architecture, record.Source))
		}
	}
	for position := range input.Artifacts {
		record := &input.Artifacts[position]
		if record.Platform == input.Platform && record.SBOM.Name != "" {
			urls = append(urls, artifactURL(record.SBOM.Name, record.SBOM.Version))
		}
	}
	return urls
}

// matching returns the locked products an imported one names.
func (known productSet) matching(named *product) []product {
	found := make([]product, 0, 2)
	for _, candidate := range known {
		if named.covers(&candidate) {
			found = append(found, candidate)
		}
	}
	return found
}

// checkEligible refuses a product that names another architecture or distribution, which
// would mean the document is about an image this one is not.
func checkEligible(named *product, platform string, known productSet) error {
	if named.kind != "deb" && named.kind != "generic" {
		return fmt.Errorf("unsupported product type %q", named.kind)
	}
	arch := named.qualifiers["arch"]
	if arch != "" && arch != "all" && arch != nativeArch(platform) {
		return fmt.Errorf("product %s names architecture %q, but this image is %s",
			named.name, arch, platform)
	}
	distro := named.qualifiers["distro"]
	if distro == "" {
		return nil
	}
	for _, candidate := range known {
		if candidate.qualifiers["distro"] == distro {
			return nil
		}
	}
	return fmt.Errorf("product %s names distribution %q, which the lock does not hold",
		named.name, distro)
}

// nativeArch returns the architecture a platform names.
func nativeArch(platform string) string {
	for _, arch := range []string{"arm64", "amd64", "riscv64", "ppc64le", "s390x", "arm"} {
		if len(platform) > len(arch) && platform[len(platform)-len(arch)-1:] == "/"+arch {
			return arch
		}
	}
	return ""
}

// Coalesce applies the merge rules to claims from any source. Claims stating the same
// thing about different products become one claim listing both, in the order they were
