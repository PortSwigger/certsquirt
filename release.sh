export VERSION=`cat VERSION`
git archive --prefix=certsquirt-${VERSION}/ --format=tar.gz --output=certsquirt-${VERSION}.tar.gz main

# crypto11/pkcs11 has issues cross compiling.  This is expected to fail.
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-macos-arm64
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-macos-amd64
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-windows-amd64.exe
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-linux-amd64
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-linux-arm64
CGO_ENABLED=1 GOOS=freebsd GOARCH=amd64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-freebsd-amd64
CGO_ENABLED=1 GOOS=freebsd GOARCH=arm64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-freebsd-arm64
CGO_ENABLED=1 GOOS=openbsd GOARCH=amd64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-openbsd-amd64
CGO_ENABLED=1 GOOS=openbsd GOARCH=arm64 go build -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" -o certsquirt-${VERSION}-openbsd-arm64
