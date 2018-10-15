#!/bin/bash

# Fetches the version of OpenSSL specified in $SSL_VERS and reconfigures the
# sources for use in a Swift module.

SSL_VERS=1.0.2p

# cd to this script's directory (cannot have spaces in path)
cd $(dirname $(cd "${BASH_SOURCE[0]%/*}" && echo "$PWD/${0##*/}"))

# download and configure OpenSSL
if [ ! -z "${SSL_VERS}" ] && [ ! -d openssl-${SSL_VERS}/openssl-${SSL_VERS} ]
then
	mkdir -pv openssl-${SSL_VERS}/COpenSSL-src
	cd openssl-${SSL_VERS}
	if [ ! -d openssl*/ ]
	then
		if [ ! -f *.tar.gz ]
		then
			curl -OL https://www.openssl.org/source/openssl-${SSL_VERS}.tar.gz
		fi
		tar -xzf *.tar.gz
	fi
	cd openssl*/
	./configure no-asm darwin64-x86_64-cc
	cp -a {e_os.h,e_os2.h,MacOS/buildinf.h,crypto,engines,ssl} ../COpenSSL-src/
	cd ../..
	rm -rf COpenSSL-src
	mv openssl-${SSL_VERS}/COpenSSL-src .
fi

# prune & reconfigure source files
RMV="ssl/ssl_task.c \
	crypto/ripemd/asm/rips.cpp \
	crypto/x509v3/v3conf.c \
	crypto/LPdir_vms.c crypto/LPdir_nyi.c crypto/LPdir_win*.c \
	crypto/bf/bfs.cpp \
	crypto/bio/bss_rtcp.c \
	crypto/bn/exp.c \
	crypto/cast/casts.cpp \
	crypto/arm_arch.h \
	crypto/armcap.c \
	crypto/ppc_arch.h \
	crypto/ppccap.c \
	crypto/s390xcap.c \
	crypto/sparc_arch.h \
	crypto/sparcv9cap.c \
	crypto/vms_rms.h \
	crypto/des/times \
	crypto/des/read_pwd.c \
	crypto/store \
	crypto/jpake \
	crypto/md2 \
	crypto/evp/e_dsa.c \
	crypto/rc5 \
	crypto/bf/bf_opts.c \
	crypto/bf/bfspeed.c \
	crypto/bn/bnspeed.c \
	crypto/bn/expspeed.c \
	crypto/cast/cast_spd.c \
	crypto/cast/castopts.c \
	crypto/conf/cnf_save.c \
	crypto/des/des.c \
	crypto/des/des3s.cpp \
	crypto/des/des_opts.c \
	crypto/des/dess.cpp \
	crypto/des/rpw.c \
	crypto/des/speed.c \
	crypto/dh/p1024.c \
	crypto/dh/p192.c \
	crypto/dh/p512.c \
	crypto/dsa/dsagen.c \
	crypto/idea/idea_spd.c \
	crypto/md4/md4.c \
	crypto/md4/md4s.cpp \
	crypto/md5/md5.c \
	crypto/md5/md5s.cpp \
	crypto/modes/cts128.c \
	crypto/rc2/rc2speed.c \
	crypto/rc4/rc4.c \
	crypto/rc4/rc4s.cpp \
	crypto/rc4/rc4speed.c \
	crypto/ripemd/rmd160.c \
	crypto/sha/sha.c \
	crypto/sha/sha1.c \
	crypto/ec/ecp_nistz256.c \
	crypto/ec/ecp_nistz256_table.c \
	crypto/aes/aes_x86core.c \
	crypto/bf/bf_cbc.c \
	crypto/rc2/tab.c \
	crypto/sha/sha256t.c \
	crypto/sha/sha512t.c \
	crypto/x509v3/v3prin.c \
	engines/ccgost/gostsum.c \
	crypto/bn/asm/x86_64-gcc.c \
	crypto/bn/vms-helper.c"

if [ -d COpenSSL-src ]
then
	echo -n "Flattening sources... "
	cd COpenSSL-src
	rm -rf $RMV

	find . -iname "*test.c" -exec rm {} \;

	find . -type f \( -iname "*.h" -o -iname "*.c" \) -exec sed -i '' -e 's#include <openssl/#include <#g' {} \;
	find . -type f \( -iname "*.h" -o -iname "*.c" \) -exec sed -i '' -e 's#include "openssl/#include "#g' {} \;
	find . -type f \( -iname "*.h" -o -iname "*.c" \) -exec sed -i '' -e 's#include "../../#include "#g' {} \;
	find . -type f \( -iname "*.h" -o -iname "*.c" \) -exec sed -i '' -e 's#include "../crypto/#include "#g' {} \;
	find . -type f \( -iname "*.h" -o -iname "*.c" \) -exec sed -i '' -e 's#include "vendor_defns/#include "#g' {} \;

	mv crypto/LPdir_unix.c crypto/LPdir_unix.h
	mv crypto/pkcs7/pk7_enc.c crypto/pkcs7/pk7_enc.h
	mv crypto/des/ncbc_enc.c crypto/des/ncbc_enc.h

	mkdir -p openssl
	rm -f openssl/*
	cd openssl
	find ../crypto -iname "*.h" -exec mv {} . \;
	find ../ssl -iname "*.h" -exec mv {} . \;
	find ../engines -iname "*.h" -exec mv {} . \;
	cd ..
	mv openssl/* .

	sed -i '' -e 's#include "LPdir_unix.c"#include "LPdir_unix.h"#g' crypto/o_dir.c
	sed -i '' -e 's#include "ncbc_enc.c"#include "ncbc_enc.h"#g' crypto/des/cbc_enc.c
	sed -i '' -e 's#include "ncbc_enc.c"#include "ncbc_enc.h"#g' crypto/des/des_enc.c

	cd openssl
	find ../crypto -iname "*.c" -exec mv {} . \;
	find ../ssl -iname "*.c" -exec mv {} . \;
	find ../engines -iname "*.c" -exec mv {} . \;
	cd ..
	mv openssl/* .

	rm -rf openssl crypto engines ssl

	for header in *.h
	do
		GRP=`grep -l -s "include <$header>" *`
		for fnd in $GRP
		do
			sed -i '' -e "s#include <$header>#include \"$header\"#g" $fnd;
		done
	done

	sed -i '' -e "s#define BN_MASK #define BN_MASK //#g" bn.h

	cd ..
	mv COpenSSL-src/ COpenSSL-flat/
	echo "done."
fi

# amalgamate source files named with these prefixes
# not included: b_ des_ e_ ecp_ m_ tb_
PREFIXES="a_ aes_ asn_ asn1_ bf_ bio_ bn_ bss_ buf_ by_ c_ cbc_ cm_ cmll_ cms_ \
	comp_ conf_ d1_ d2i_ dh_ dsa_ dso_ ec_ ec2_ ech_ ecs_ enc_ eng_ err_ evp_ \
	f_ gost_ hm_ i_ i2d_ md4_ md5_ mem_ o_ obj_ ocsp_ p_ p5_ p12_ pcy_ pem_ \
	pk7_ pmeth_ rand_ rc2_ rc4_ rmd_ rsa_ s2_ s3_ s23_ seed_ sha_ srp_ ssl_ t_ \
	t1_ tasn_ ts_ ui_ v3_ wp_ x_ x509_"

if [ -d COpenSSL-flat ]
then
	mv COpenSSL-flat/ COpenSSL-combined/
	# fetch and patch the amalgamation script
	if [ ! -x amalgamate_.py ]
	then
		curl -OL https://raw.githubusercontent.com/edlund/amalgamate/master/amalgamate.py
		chmod +x amalgamate.py
		patch -p0 <<EOF
--- amalgamate.py	2017-10-30 12:29:21.000000000 -0400
+++ amalgamate_.py	2017-10-30 12:23:04.000000000 -0400
@@ -38,6 +38,7 @@
 import os
 import re
 import sys
+import io
 
 class Amalgamation(object):
 	
@@ -73,10 +74,10 @@
 	
 	# Generate the amalgamation and write it to the target file.
 	def generate(self):
-		amalgamation = ""
+		amalgamation = u""
 		
 		if self.prologue:
-			with open(self.prologue, 'r') as f:
+			with io.open(self.prologue, 'r',encoding='utf8') as f:
 				amalgamation += datetime.datetime.now().strftime(f.read())
 		
 		if self.verbose:
@@ -93,7 +94,7 @@
 			t = TranslationUnit(file_path, self, True)
 			amalgamation += t.content
 		
-		with open(self.target, 'w') as f:
+		with io.open(self.target, 'w',encoding='utf8') as f:
 			f.write(amalgamation)
 		
 		print("...done!\n")
@@ -117,7 +118,7 @@
 	# directives where macros and defines needs to expanded is
 	# not a concern right now.
 	include_pattern = re.compile(
-		r'#\s*include\s+(<|")(?P<path>.*?)("|>)', re.S)
+		r'#include\s+(<|")(?P<path>.*?)("|>)', re.S)
 
 	# #pragma once
 	pragma_once_pattern = re.compile(r'#\s*pragma\s+once', re.S)
@@ -193,7 +194,7 @@
 		
 		# Handle all collected pragma once directives.
 		prev_end = 0
-		tmp_content = ''
+		tmp_content = u''
 		for pragma_match in pragmas:
 			tmp_content += self.content[prev_end:pragma_match.start()]
 			prev_end = pragma_match.end()
@@ -228,14 +229,15 @@
 		
 		# Handle all collected include directives.
 		prev_end = 0
-		tmp_content = ''
+		tmp_content = u''
 		for include in includes:
 			include_match, found_included_path = include
 			tmp_content += self.content[prev_end:include_match.start()]
-			tmp_content += "// {0}\n".format(include_match.group(0))
 			if not found_included_path in self.amalgamation.included_files:
+				tmp_content += "{0}".format(include_match.group(0))
 				t = TranslationUnit(found_included_path, self.amalgamation, False)
-				tmp_content += t.content
+			else:
+			    tmp_content += "// {0}".format(include_match.group(0))
 			prev_end = include_match.end()
 		tmp_content += self.content[prev_end:]
 		self.content = tmp_content
@@ -259,7 +261,7 @@
 		actual_path = self.amalgamation.actual_path(file_path)
 		if not os.path.isfile(actual_path):
 			raise IOError("File not found: \"{0}\"".format(file_path))
-		with open(actual_path, 'r') as f:
+		with io.open(actual_path, 'r',encoding='utf8') as f:
 			self.content = f.read()
 			self._process()
 
EOF
		mv amalgamate.py amalgamate_.py
	fi

	# skip a few specific files
	mv COpenSSL-combined/{d1_lib.c,v3_lib.c} .

	# for each prefix, generate a .json file for all matching .c files
	# unless the amalgamated .c file is already present
	for p in ${PREFIXES}
	do
		FIRST=true
		JSON=${p}.c.json
		BATCH=$(cd COpenSSL-combined; ls ${p}*.c)
		if [ "${BATCH}" == ${p}.c ]
		then
			continue
		fi
		echo '{
		"project": "COpenSSL-combined",
		"target": "'${p}'.c",
		"sources": [' > "${JSON}"
		for b in ${BATCH}
		do
			if ${FIRST}
			then
				echo '      "'${b}'"' >> "${JSON}"
				FIRST=false
			else
				echo '      ,"'${b}'"' >> "${JSON}"
			fi
		done
		echo '  ],
		"include_paths": [
			"."
		]
	}' >> "${JSON}"
	done

	# perform amalgamation and swap in new sources for originals, then remove .json files
	for j in $(find . -name "*.c.json"); do
		./amalgamate_.py -v=no -c ${j} -s COpenSSL-combined/
		PREFIX=${j%.c.json}
		find COpenSSL-combined -name "${PREFIX#*/}*".c -exec mv {} openssl-${SSL_VERS}/ \;
		mv "${PREFIX#*/}"*.c COpenSSL-combined/
		find ${j} -exec rm -f {} \;
	done
	
	mv COpenSSL-combined/ COpenSSL/
fi

if [ -d COpenSSL ]
then
	cp -a ../COpenSSL/include COpenSSL/
	rm -rf COpenSSL-orig
	mv ../COpenSSL/ COpenSSL-orig/
	mv COpenSSL/ ..
	echo "Update complete. Remember to remove amalgamate_.py, COpenSSL-orig/, and openssl-${SSL_VERS}/ from this directory."
fi

# HEADERS="aes.h bn.h comp.h dh.h ec.h hmac.h md5.h opensslconf.h pkcs7.h rsa.h ssl.h tls1.h x509.h \
#		asn1.h buffer.h conf.h dsa.h ecdh.h idea.h mdc2.h opensslv.h pqueue.h safestack.h	ssl2.h ts.h x509_vfy.h \
#		asn1_mac.h camellia.h conf_api.h dso.h ecdsa.h krb5_asn.h modes.h ossl_typ.h rand.h seed.h ssl23.h txt_db.h x509v3.h \
#		asn1t.h cast.h crypto.h dtls1.h engine.h kssl.h obj_mac.h pem.h rc2.h sha.h ssl3.h ui.h \
#		bio.h cmac.h des.h e_os2.h err.h lhash.h objects.h pem2.h rc4.h srp.h stack.h ui_compat.h \
#		blowfish.h cms.h des_old.h ebcdic.h evp.h md4.h ocsp.h pkcs12.h ripemd.h srtp.h symhacks.h whrlpool.h"
# 
# mkdir -p include/Headers
# cd include/Headers
# rm *.h
# 
# for header in $HEADERS
# do
#	cp "../../$header" .
# done

# for header in *.h
# do
#	GRP=`grep -l -s "include \"$header\"" *`
#	for fnd in $GRP
#	do
#		sed -i '' -e "s#include \"$header\"#include \"OpenSSL/$header\"#g" $fnd;
#	done
# done
