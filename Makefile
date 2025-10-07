fmt:
	find . -name '*.go' -exec gofumpt -s -extra -w {} \;