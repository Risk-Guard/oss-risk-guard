package git

import (
	"fmt"

	"github.com/go-git/go-git/v5"
)

func GetHeadCommit(repoPath string) (string, error) {
	repo, err := git.PlainOpenWithOptions(repoPath, &git.PlainOpenOptions{EnableDotGitCommonDir: true})
	if err != nil {
		return "", fmt.Errorf("opening repository: %w", err)
	}
	ref, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("getting HEAD: %w", err)
	}
	return ref.Hash().String(), nil
}
