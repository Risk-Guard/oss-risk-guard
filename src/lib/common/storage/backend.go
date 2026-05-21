package storage

type Backend interface {
	Metadata() MetadataBackend
	Checks() ChecksBackend
}
