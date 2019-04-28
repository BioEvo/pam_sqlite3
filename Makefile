LIBSRC=     pam_sqlite3.c
LIBOBJ=     pam_sqlite3.o
LIBLIB=     pam_sqlite3.so

LINK=		-L/usr/lib
LDLIBS=		${LINK} -lpam  -lssl -lcrypto -lsqlite3 -lpam_misc
INCLUDE=	-I/usr/include
CFLAGS=		 -fPIC -DPIC -Wall -D_GNU_SOURCE ${INCLUDE}


all: ${LIBLIB}

DISTFILES= pam_sqlite3.c

${LIBLIB}: ${LIBOBJ}
	${CC} ${CFLAGS} ${INCLUDE} -shared -o $@ ${LIBOBJ} ${LDLIBS} 

install:
	cp -f ${LIBLIB} /lib64/security/

clean:
	rm -f ${LIBOBJ}

