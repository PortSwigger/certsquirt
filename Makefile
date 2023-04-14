all:
	./version.sh
	go build -v -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" || exit

clean:
	rm -- certsquirt 

release: all
	./release.sh

realclean:
	rm -f *.crt *.pem *.key
	rm -f *.tar.gz
