package filesystem

const (
	pathDirectory = "directory"
	pathFile      = "file"
	pathSymlink   = "symlink"
)

// Filesystem declares image entries and synthesized OS state, without accessing it.
type Filesystem struct {
	Paths     []Path            `yaml:"paths" json:"paths"`
	Accounts  Accounts          `yaml:"accounts" json:"accounts"`
	Timezone  *string           `yaml:"timezone" json:"timezone"`
	CA        *CABundle         `yaml:"ca" json:"ca"`
	OSRelease map[string]string `yaml:"os-release" json:"os-release"`
}

// Path creates an entry or applies metadata without truncating file bytes.
type Path struct {
	Path   string  `yaml:"path" json:"path"`
	Type   string  `yaml:"type" json:"type"`
	Mode   *string `yaml:"mode" json:"mode"`
	UID    int     `yaml:"uid" json:"uid"`
	GID    int     `yaml:"gid" json:"gid"`
	Target *string `yaml:"target" json:"target"`
}

// Accounts declares explicit password-disabled users and groups, independent of runtime user.
type Accounts struct {
	Users  []UserAccount  `yaml:"users" json:"users"`
	Groups []GroupAccount `yaml:"groups" json:"groups"`
}

// UserAccount declares a user with explicit IDs; home and shell are account metadata only.
type UserAccount struct {
	Name  string  `yaml:"name" json:"name"`
	UID   *int    `yaml:"uid" json:"uid"`
	GID   *int    `yaml:"gid" json:"gid"`
	Home  *string `yaml:"home" json:"home"`
	Shell *string `yaml:"shell" json:"shell"`
}

// GroupAccount declares a group with an explicit numeric ID.
type GroupAccount struct {
	Name string `yaml:"name" json:"name"`
	GID  *int   `yaml:"gid" json:"gid"`
}

// CABundle selects explicit public certificate inputs and append/replace policy.
type CABundle struct {
	Mode    string   `yaml:"mode" json:"mode"`
	Sources []string `yaml:"sources" json:"sources"`
}
