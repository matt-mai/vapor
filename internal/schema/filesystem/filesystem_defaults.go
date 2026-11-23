package filesystem

// ApplyDefaults fills unset file modes, account homes, shells and CA bundle paths.
func ApplyDefaults(filesystem *Filesystem) {
	for i := range filesystem.Paths {
		entry := &filesystem.Paths[i]
		if entry.Mode != nil {
			continue
		}
		switch entry.Type {
		case pathDirectory:
			entry.Mode = new("0755")
		case pathFile:
			entry.Mode = new("0644")
		case pathSymlink:
			entry.Mode = new("0777")
		}
	}
	for i := range filesystem.Accounts.Users {
		user := &filesystem.Accounts.Users[i]
		if user.Home == nil {
			user.Home = new("/")
		}
		if user.Shell == nil {
			user.Shell = new("/sbin/nologin")
		}
	}
}
