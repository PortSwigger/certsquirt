export VERSION=`cat VERSION`
git archive --prefix=certsquirt-${VERSION}/ --format=tar.gz --output=certsquirt-${VERSION}.tar.gz main
