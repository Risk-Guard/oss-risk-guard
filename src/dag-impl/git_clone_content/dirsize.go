package git_clone_content

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type repoSize struct {
	git     int64
	content int64
}

func (r repoSize) total() int64 { return r.git + r.content }

func repoDirSize(root string) (repoSize, error) {
	gitPrefix := filepath.Join(root, ".git") + string(filepath.Separator)
	var s repoSize
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if path == filepath.Join(root, ".git") || strings.HasPrefix(path, gitPrefix) {
			s.git += info.Size()
		} else {
			s.content += info.Size()
		}
		return nil
	})
	return s, err
}

func humanizeBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
