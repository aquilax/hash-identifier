package hashid

import (
	"regexp"
)

// HashID is a type of hash
type HashID = int

const (
	CRC_16 HashID = 1 + iota
	CRC_16_CCITT
	FCS_16
	Adler_32
	CRC_32B
	FCS_32
	GHash_32_3
	GHash_32_5
	FNV_132
	Fletcher_32
	Joaat
	ELF_32
	XOR_32
	CRC_24
	CRC_32
	Eggdrop_IRC_Bot
	DES_Unix
	Traditional_DES
	DEScrypt
	MySQL323
	DES_Oracle
	Half_MD5
	Oracle_7_10g
	FNV_164
	CRC_64
	Cisco_PIX_MD5
	Lotus_Notes_Domino_6
	BSDi_Crypt
	CRC_96_ZIP
	Crypt16
	MD2
	MD5
	MD4
	Double_MD5
	LM
	RIPEMD_128
	Haval_128
	Tiger_128
	Skein_256_128
	Skein_512_128
	Lotus_Notes_Domino_5
	Skype
	ZipMonster
	PrestaShop
	Md5_md5_md5_pass
	Md5_strtoupper_md5_pass
	Md5_sha1_pass
	Md5_pass_salt
	Md5_salt_pass
	Md5_unicode_pass_salt
	Md5_salt_unicode_pass
	HMAC_MD5_key_pass
	HMAC_MD5_key_salt
	Md5_md5_salt_pass
	Md5_salt_md5_pass
	Md5_pass_md5_salt
	Md5_salt_pass_salt
	Md5_md5_pass_md5_salt
	Md5_salt_md5_salt_pass
	Md5_salt_md5_pass_salt
	Md5_username_0_pass
	Snefru_128
	NTLM
	Domain_Cached_Credentials
	Domain_Cached_Credentials_2
	SHA_1_Base64
	Netscape_LDAP_SHA
	MD5_Crypt
	Cisco_IOS_MD5
	FreeBSD_MD5
	Lineage_II_C4
	PhpBB_v3_x
	Wordpress_v2_6_0_2_6_1
	PHPass_Portable_Hash
	Wordpress_v2_6_2
	Joomla_v2_5_18
	OsCommerce
	Xt_Commerce
	MD5_APR
	Apache_MD5
	Md5apr1
	AIX_smd5
	WebEdition_CMS
	IP_Board_v2
	MyBB_v1_2
	CryptoCurrency_Adress
	SHA_1
	Double_SHA_1
	RIPEMD_160
	Haval_160
	Tiger_160
	HAS_160
	LinkedIn
	Skein_256_160
	Skein_512_160
	MangosWeb_Enhanced_CMS
	Sha1_sha1_sha1_pass
	Sha1_md5_pass
	Sha1_pass_salt
	Sha1_salt_pass
	Sha1_unicode_pass_salt
	Sha1_salt_unicode_pass
	HMAC_SHA1_key_pass
	HMAC_SHA1_key_salt
	Sha1_salt_pass_salt
	MySQL5_x
	MySQL4_1
	Cisco_IOS_SHA_256
	SSHA_1_Base64
	Netscape_LDAP_SSHA
	Nsldaps
	Fortigate_FortiOS
	Haval_192
	Tiger_192
	SHA_1_Oracle
	OSX_v10_4
	OSX_v10_5
	OSX_v10_6
	Palshop_CMS
	CryptoCurrency_PrivateKey
	AIX_ssha1
	MSSQL_2005
	MSSQL_2008
	Sun_MD5_Crypt
	SHA_224
	Haval_224
	SHA3_224
	Skein_256_224
	Skein_512_224
	Blowfish_OpenBSD
	Woltlab_Burning_Board_4_x
	Bcrypt
	Android_PIN
	Oracle_11g_12c
	Bcrypt_SHA_256
	VBulletin_v3_8_5
	Snefru_256
	SHA_256
	RIPEMD_256
	Haval_256
	GOST_R_34_11_94
	GOST_CryptoPro_S_Box
	SHA3_256
	Skein_256
	Skein_512_256
	Ventrilo
	Sha256_pass_salt
	Sha256_salt_pass
	Sha256_unicode_pass_salt
	Sha256_salt_unicode_pass
	HMAC_SHA256_key_pass
	HMAC_SHA256_key_salt
	SAM_LM_Hash_NT_Hash
	MD5_Chap
	ISCSI_CHAP_Authentication
	EPiServer_6_x_v4
	AIX_ssha256
	RIPEMD_320
	MSSQL_2000
	SHA_384
	SHA3_384
	Skein_512_384
	Skein_1024_384
	SSHA_512_Base64
	LDAP_SSHA_512
	AIX_ssha512
	SHA_512
	Whirlpool
	Salsa10
	Salsa20
	SHA3_512
	Skein_512
	Skein_1024_512
	Sha512_pass_salt
	Sha512_salt_pass
	Sha512_unicode_pass_salt
	Sha512_salt_unicode_pass
	HMAC_SHA512_key_pass
	HMAC_SHA512_key_salt
	OSX_v10_7
	MSSQL_2012
	MSSQL_2014
	OSX_v10_8
	OSX_v10_9
	Skein_1024
	GRUB_2
	Django_SHA_1
	Citrix_Netscaler
	Drupal_v7_x
	SHA_256_Crypt
	Sybase_ASE
	SHA_512_Crypt
	Minecraft_AuthMe_Reloaded
	Django_SHA_256
	Django_SHA_384
	Clavister_Secure_Gateway
	Cisco_VPN_Client_PCF_File
	Microsoft_MSTSC_RDP_File
	NetNTLMv1_VANILLA_NetNTLMv1_ESS
	NetNTLMv2
	Kerberos_5_AS_REQ_Pre_Auth
	SCRAM_Hash
	Redmine_Project_Management_Web_App
	SAP_CODVN_B_BCODE
	SAP_CODVN_F_G_PASSCODE
	Juniper_Netscreen_SSG_ScreenOS
	EPi
	SMF_v1_1
	Woltlab_Burning_Board_3_x
	IPMI2_RAKP_HMAC_SHA1
	Lastpass
	Cisco_ASA_MD5
	VNC
	DNSSEC_NSEC3
	RACF
	NTHash_FreeBSD_Variant
	SHA_1_Crypt
	HMailServer
	MediaWiki
	Minecraft_xAuth
	PBKDF2_SHA1_Generic
	PBKDF2_SHA256_Generic
	PBKDF2_SHA512_Generic
	PBKDF2_Cryptacular
	PBKDF2_Dwayne_Litzenberger
	Fairly_Secure_Hashed_Password
	PHPS
	OnePassword_Agile_Keychain
	OnePassword_Cloud_Keychain
	IKE_PSK_MD5
	IKE_PSK_SHA1
	PeopleSoft
	Django_DES_Crypt_Wrapper
	Django_PBKDF2_HMAC_SHA256
	Django_PBKDF2_HMAC_SHA1
	Django_bcrypt
	Django_MD5
	PBKDF2_Atlassian
	PostgreSQL_MD5
	Lotus_Notes_Domino_8
	Scrypt
	Cisco_Type_8
	Cisco_Type_9
	Microsoft_Office_2007
	Microsoft_Office_2010
	Microsoft_Office_2013
	Android_FDE_4_3
	Microsoft_Office_2003_MD5_RC4
	Microsoft_Office_2003_MD5_RC4_collider_mode_1
	Microsoft_Office_2003_MD5_RC4_collider_mode_2
	Microsoft_Office_2003_SHA1_RC4
	Microsoft_Office_2003_SHA1_RC4_collider_mode_1
	Microsoft_Office_2003_SHA1_RC4_collider_mode_2
	RAdmin_v2_x
	SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1
	CRAM_MD5
	SipHash
	Cisco_Type_7
	BigCrypt
	Cisco_Type_4
	Django_bcrypt_SHA256
	PostgreSQL_Challenge_Response_Authentication_MD5
	Siemens_S7
	Microsoft_Outlook_PST
	PBKDF2_HMAC_SHA256_PHP
	Dahua
	MySQL_Challenge_Response_Authentication_SHA1
	PDF_1_4_1_6_Acrobat_5_8
)

var HashNames = map[HashID]string{
	CRC_16:                             "CRC-16",
	CRC_16_CCITT:                       "CRC-16-CCITT",
	FCS_16:                             "FCS-16",
	Adler_32:                           "Adler-32",
	CRC_32B:                            "CRC-32B",
	FCS_32:                             "FCS-32",
	GHash_32_3:                         "GHash-32-3",
	GHash_32_5:                         "GHash-32-5",
	FNV_132:                            "FNV-132",
	Fletcher_32:                        "Fletcher-32",
	Joaat:                              "Joaat",
	ELF_32:                             "ELF-32",
	XOR_32:                             "XOR-32",
	CRC_24:                             "CRC-24",
	CRC_32:                             "CRC-32",
	Eggdrop_IRC_Bot:                    "Eggdrop IRC Bot",
	DES_Unix:                           "DES(Unix)",
	Traditional_DES:                    "Traditional DES",
	DEScrypt:                           "DEScrypt",
	MySQL323:                           "MySQL323",
	DES_Oracle:                         "DES(Oracle)",
	Half_MD5:                           "Half MD5",
	Oracle_7_10g:                       "Oracle 7-10g",
	FNV_164:                            "FNV-164",
	CRC_64:                             "CRC-64",
	Cisco_PIX_MD5:                      "Cisco-PIX(MD5)",
	Lotus_Notes_Domino_6:               "Lotus Notes/Domino 6",
	BSDi_Crypt:                         "BSDi Crypt",
	CRC_96_ZIP:                         "CRC-96(ZIP)",
	Crypt16:                            "Crypt16",
	MD2:                                "MD2",
	MD5:                                "MD5",
	MD4:                                "MD4",
	Double_MD5:                         "Double MD5",
	LM:                                 "LM",
	RIPEMD_128:                         "RIPEMD-128",
	Haval_128:                          "Haval-128",
	Tiger_128:                          "Tiger-128",
	Skein_256_128:                      "Skein-256(128)",
	Skein_512_128:                      "Skein-512(128)",
	Lotus_Notes_Domino_5:               "Lotus Notes/Domino 5",
	Skype:                              "Skype",
	ZipMonster:                         "ZipMonster",
	PrestaShop:                         "PrestaShop",
	Md5_md5_md5_pass:                   "md5(md5(md5($pass)))",
	Md5_strtoupper_md5_pass:            "md5(strtoupper(md5($pass)))",
	Md5_sha1_pass:                      "md5(sha1($pass))",
	Md5_pass_salt:                      "md5($pass.$salt)",
	Md5_salt_pass:                      "md5($salt.$pass)",
	Md5_unicode_pass_salt:              "md5(unicode($pass).$salt)",
	Md5_salt_unicode_pass:              "md5($salt.unicode($pass))",
	HMAC_MD5_key_pass:                  "HMAC-MD5 (key = $pass)",
	HMAC_MD5_key_salt:                  "HMAC-MD5 (key = $salt)",
	Md5_md5_salt_pass:                  "md5(md5($salt).$pass)",
	Md5_salt_md5_pass:                  "md5($salt.md5($pass))",
	Md5_pass_md5_salt:                  "md5($pass.md5($salt))",
	Md5_salt_pass_salt:                 "md5($salt.$pass.$salt)",
	Md5_md5_pass_md5_salt:              "md5(md5($pass).md5($salt))",
	Md5_salt_md5_salt_pass:             "md5($salt.md5($salt.$pass))",
	Md5_salt_md5_pass_salt:             "md5($salt.md5($pass.$salt))",
	Md5_username_0_pass:                "md5($username.0.$pass)",
	Snefru_128:                         "Snefru-128",
	NTLM:                               "NTLM",
	Domain_Cached_Credentials:          "Domain Cached Credentials",
	Domain_Cached_Credentials_2:        "Domain Cached Credentials 2",
	SHA_1_Base64:                       "SHA-1(Base64)",
	Netscape_LDAP_SHA:                  "Netscape LDAP SHA",
	MD5_Crypt:                          "MD5 Crypt",
	Cisco_IOS_MD5:                      "Cisco-IOS(MD5)",
	FreeBSD_MD5:                        "FreeBSD MD5",
	Lineage_II_C4:                      "Lineage II C4",
	PhpBB_v3_x:                         "phpBB v3.x",
	Wordpress_v2_6_0_2_6_1:             "Wordpress v2.6.0/2.6.1",
	PHPass_Portable_Hash:               "PHPass' Portable Hash",
	Wordpress_v2_6_2:                   "Wordpress ≥ v2.6.2",
	Joomla_v2_5_18:                     "Joomla < v2.5.18",
	OsCommerce:                         "osCommerce",
	Xt_Commerce:                        "xt:Commerce",
	MD5_APR:                            "MD5(APR)",
	Apache_MD5:                         "Apache MD5",
	Md5apr1:                            "md5apr1",
	AIX_smd5:                           "AIX(smd5)",
	WebEdition_CMS:                     "WebEdition CMS",
	IP_Board_v2:                        "IP.Board ≥ v2+",
	MyBB_v1_2:                          "MyBB ≥ v1.2+",
	CryptoCurrency_Adress:              "CryptoCurrency(Adress)",
	SHA_1:                              "SHA-1",
	Double_SHA_1:                       "Double SHA-1",
	RIPEMD_160:                         "RIPEMD-160",
	Haval_160:                          "Haval-160",
	Tiger_160:                          "Tiger-160",
	HAS_160:                            "HAS-160",
	LinkedIn:                           "LinkedIn",
	Skein_256_160:                      "Skein-256(160)",
	Skein_512_160:                      "Skein-512(160)",
	MangosWeb_Enhanced_CMS:             "MangosWeb Enhanced CMS",
	Sha1_sha1_sha1_pass:                "sha1(sha1(sha1($pass)))",
	Sha1_md5_pass:                      "sha1(md5($pass))",
	Sha1_pass_salt:                     "sha1($pass.$salt)",
	Sha1_salt_pass:                     "sha1($salt.$pass)",
	Sha1_unicode_pass_salt:             "sha1(unicode($pass).$salt)",
	Sha1_salt_unicode_pass:             "sha1($salt.unicode($pass))",
	HMAC_SHA1_key_pass:                 "HMAC-SHA1 (key = $pass)",
	HMAC_SHA1_key_salt:                 "HMAC-SHA1 (key = $salt)",
	Sha1_salt_pass_salt:                "sha1($salt.$pass.$salt)",
	MySQL5_x:                           "MySQL5.x",
	MySQL4_1:                           "MySQL4.1",
	Cisco_IOS_SHA_256:                  "Cisco-IOS(SHA-256)",
	SSHA_1_Base64:                      "SSHA-1(Base64)",
	Netscape_LDAP_SSHA:                 "Netscape LDAP SSHA",
	Nsldaps:                            "nsldaps",
	Fortigate_FortiOS:                  "Fortigate(FortiOS)",
	Haval_192:                          "Haval-192",
	Tiger_192:                          "Tiger-192",
	SHA_1_Oracle:                       "SHA-1(Oracle)",
	OSX_v10_4:                          "OSX v10.4",
	OSX_v10_5:                          "OSX v10.5",
	OSX_v10_6:                          "OSX v10.6",
	Palshop_CMS:                        "Palshop CMS",
	CryptoCurrency_PrivateKey:          "CryptoCurrency(PrivateKey)",
	AIX_ssha1:                          "AIX(ssha1)",
	MSSQL_2005:                         "MSSQL(2005)",
	MSSQL_2008:                         "MSSQL(2008)",
	Sun_MD5_Crypt:                      "Sun MD5 Crypt",
	SHA_224:                            "SHA-224",
	Haval_224:                          "Haval-224",
	SHA3_224:                           "SHA3-224",
	Skein_256_224:                      "Skein-256(224)",
	Skein_512_224:                      "Skein-512(224)",
	Blowfish_OpenBSD:                   "Blowfish(OpenBSD)",
	Woltlab_Burning_Board_4_x:          "Woltlab Burning Board 4.x",
	Bcrypt:                             "bcrypt",
	Android_PIN:                        "Android PIN",
	Oracle_11g_12c:                     "Oracle 11g/12c",
	Bcrypt_SHA_256:                     "bcrypt(SHA-256)",
	Snefru_256:                         "Snefru-256",
	SHA_256:                            "SHA-256",
	RIPEMD_256:                         "RIPEMD-256",
	Haval_256:                          "Haval-256",
	GOST_R_34_11_94:                    "GOST R 34.11-94",
	GOST_CryptoPro_S_Box:               "GOST CryptoPro S-Box",
	SHA3_256:                           "SHA3-256",
	Skein_256:                          "Skein-256",
	Skein_512_256:                      "Skein-512(256)",
	Ventrilo:                           "Ventrilo",
	Sha256_pass_salt:                   "sha256($pass.$salt)",
	Sha256_salt_pass:                   "sha256($salt.$pass)",
	Sha256_unicode_pass_salt:           "sha256(unicode($pass).$salt)",
	Sha256_salt_unicode_pass:           "sha256($salt.unicode($pass))",
	HMAC_SHA256_key_pass:               "HMAC-SHA256 (key = $pass)",
	HMAC_SHA256_key_salt:               "HMAC-SHA256 (key = $salt)",
	SAM_LM_Hash_NT_Hash:                "SAM(LM_Hash:NT_Hash)",
	MD5_Chap:                           "MD5(Chap)",
	ISCSI_CHAP_Authentication:          "iSCSI CHAP Authentication",
	EPiServer_6_x_v4:                   "EPiServer 6.x ≥ v4",
	AIX_ssha256:                        "AIX(ssha256)",
	RIPEMD_320:                         "RIPEMD-320",
	MSSQL_2000:                         "MSSQL(2000)",
	SHA_384:                            "SHA-384",
	SHA3_384:                           "SHA3-384",
	Skein_512_384:                      "Skein-512(384)",
	Skein_1024_384:                     "Skein-1024(384)",
	SSHA_512_Base64:                    "SSHA-512(Base64)",
	LDAP_SSHA_512:                      "LDAP(SSHA-512)",
	AIX_ssha512:                        "AIX(ssha512)",
	SHA_512:                            "SHA-512",
	Whirlpool:                          "Whirlpool",
	Salsa10:                            "Salsa10",
	Salsa20:                            "Salsa20",
	SHA3_512:                           "SHA3-512",
	Skein_512:                          "Skein-512",
	Skein_1024_512:                     "Skein-1024(512)",
	Sha512_pass_salt:                   "sha512($pass.$salt)",
	Sha512_salt_pass:                   "sha512($salt.$pass)",
	Sha512_unicode_pass_salt:           "sha512(unicode($pass).$salt)",
	Sha512_salt_unicode_pass:           "sha512($salt.unicode($pass))",
	HMAC_SHA512_key_pass:               "HMAC-SHA512 (key = $pass)",
	HMAC_SHA512_key_salt:               "HMAC-SHA512 (key = $salt)",
	OSX_v10_7:                          "OSX v10.7",
	MSSQL_2012:                         "MSSQL(2012)",
	MSSQL_2014:                         "MSSQL(2014)",
	OSX_v10_8:                          "OSX v10.8",
	OSX_v10_9:                          "OSX v10.9",
	Skein_1024:                         "Skein-1024",
	GRUB_2:                             "GRUB 2",
	Django_SHA_1:                       "Django(SHA-1)",
	Citrix_Netscaler:                   "Citrix Netscaler",
	Drupal_v7_x:                        "Drupal > v7.x",
	SHA_256_Crypt:                      "SHA-256 Crypt",
	Sybase_ASE:                         "Sybase ASE",
	SHA_512_Crypt:                      "SHA-512 Crypt",
	Minecraft_AuthMe_Reloaded:          "Minecraft(AuthMe Reloaded)",
	Django_SHA_256:                     "Django(SHA-256)",
	Django_SHA_384:                     "Django(SHA-384)",
	Clavister_Secure_Gateway:           "Clavister Secure Gateway",
	Cisco_VPN_Client_PCF_File:          "Cisco VPN Client(PCF-File)",
	Microsoft_MSTSC_RDP_File:           "Microsoft MSTSC(RDP-File)",
	NetNTLMv1_VANILLA_NetNTLMv1_ESS:    "NetNTLMv1-VANILLA / NetNTLMv1+ESS",
	NetNTLMv2:                          "NetNTLMv2",
	Kerberos_5_AS_REQ_Pre_Auth:         "Kerberos 5 AS-REQ Pre-Auth",
	SCRAM_Hash:                         "SCRAM Hash",
	Redmine_Project_Management_Web_App: "Redmine Project Management Web App",
	SAP_CODVN_B_BCODE:                  "SAP CODVN B (BCODE)",
	SAP_CODVN_F_G_PASSCODE:             "SAP CODVN F/G (PASSCODE)",
	Juniper_Netscreen_SSG_ScreenOS:     "Juniper Netscreen/SSG(ScreenOS)",
	EPi:                                "EPi",
	SMF_v1_1:                           "SMF ≥ v1.1",
	Woltlab_Burning_Board_3_x:          "Woltlab Burning Board 3.x",
	IPMI2_RAKP_HMAC_SHA1:               "IPMI2 RAKP HMAC-SHA1",
	Lastpass:                           "Lastpass",
	Cisco_ASA_MD5:                      "Cisco-ASA(MD5)",
	VNC:                                "VNC",
	DNSSEC_NSEC3:                       "DNSSEC(NSEC3)",
	RACF:                               "RACF",
	NTHash_FreeBSD_Variant:             "NTHash(FreeBSD Variant)",
	SHA_1_Crypt:                        "SHA-1 Crypt",
	HMailServer:                        "hMailServer",
	MediaWiki:                          "MediaWiki",
	Minecraft_xAuth:                    "Minecraft(xAuth)",
	PBKDF2_SHA1_Generic:                "PBKDF2-SHA1(Generic)",
	PBKDF2_SHA256_Generic:              "PBKDF2-SHA256(Generic)",
	PBKDF2_SHA512_Generic:              "PBKDF2-SHA512(Generic)",
	PBKDF2_Cryptacular:                 "PBKDF2(Cryptacular)",
	PBKDF2_Dwayne_Litzenberger:         "PBKDF2(Dwayne Litzenberger)",
	Fairly_Secure_Hashed_Password:      "Fairly Secure Hashed Password",
	PHPS:                               "PHPS",
	OnePassword_Agile_Keychain:         "1Password(Agile Keychain)",
	OnePassword_Cloud_Keychain:         "1Password(Cloud Keychain)",
	IKE_PSK_MD5:                        "IKE-PSK MD5",
	IKE_PSK_SHA1:                       "IKE-PSK SHA1",
	PeopleSoft:                         "PeopleSoft",
	Django_DES_Crypt_Wrapper:           "Django(DES Crypt Wrapper)",
	Django_PBKDF2_HMAC_SHA256:          "Django(PBKDF2-HMAC-SHA256)",
	Django_PBKDF2_HMAC_SHA1:            "Django(PBKDF2-HMAC-SHA1)",
	Django_bcrypt:                      "Django(bcrypt)",
	Django_MD5:                         "Django(MD5)",
	PBKDF2_Atlassian:                   "PBKDF2(Atlassian)",
	PostgreSQL_MD5:                     "PostgreSQL MD5",
	Lotus_Notes_Domino_8:               "Lotus Notes/Domino 8",
	Scrypt:                             "scrypt",
	Cisco_Type_8:                       "Cisco Type 8",
	Cisco_Type_9:                       "Cisco Type 9",
	Microsoft_Office_2007:              "Microsoft Office 2007",
	Microsoft_Office_2010:              "Microsoft Office 2010",
	Microsoft_Office_2013:              "Microsoft Office 2013",
	Android_FDE_4_3:                    "Android FDE ≤ 4.3",
	Microsoft_Office_2003_MD5_RC4:      "Microsoft Office ≤ 2003 (MD5+RC4)",
	Microsoft_Office_2003_MD5_RC4_collider_mode_1:  "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1",
	Microsoft_Office_2003_MD5_RC4_collider_mode_2:  "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2",
	Microsoft_Office_2003_SHA1_RC4:                 "Microsoft Office ≤ 2003 (SHA1+RC4)",
	Microsoft_Office_2003_SHA1_RC4_collider_mode_1: "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1",
	Microsoft_Office_2003_SHA1_RC4_collider_mode_2: "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2",
	RAdmin_v2_x:                       "RAdmin v2.x",
	SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
	CRAM_MD5:                          "CRAM-MD5",
	SipHash:                           "SipHash",
	Cisco_Type_7:                      "Cisco Type 7",
	BigCrypt:                          "BigCrypt",
	Cisco_Type_4:                      "Cisco Type 4",
	Django_bcrypt_SHA256:              "Django(bcrypt-SHA256)",
	PostgreSQL_Challenge_Response_Authentication_MD5: "PostgreSQL Challenge-Response Authentication (MD5)",
	Siemens_S7:             "Siemens-S7",
	Microsoft_Outlook_PST:  "Microsoft Outlook PST",
	PBKDF2_HMAC_SHA256_PHP: "PBKDF2-HMAC-SHA256(PHP)",
	Dahua:                  "Dahua",
	MySQL_Challenge_Response_Authentication_SHA1: "MySQL Challenge-Response Authentication (SHA1)",
	PDF_1_4_1_6_Acrobat_5_8:                      "PDF 1.4 - 1.6 (Acrobat 5 - 8)",
}

type Prototype struct {
	Re    *regexp.Regexp
	Modes []HashInfo
}

type HashInfo struct {
	ID       HashID
	Hashcat  string
	John     string
	Extended bool
}

func (hi HashInfo) Name() string {
	return HashNames[hi.ID]
}

func GetDefaultPrototypes() []Prototype {
	return []Prototype{
		{
			regexp.MustCompile("(?i)^[a-f0-9]{4}$"),
			[]HashInfo{
				{ID: CRC_16, Hashcat: "", John: "", Extended: false},
				{ID: CRC_16_CCITT, Hashcat: "", John: "", Extended: false},
				{ID: FCS_16, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: Adler_32, Hashcat: "", John: "", Extended: false},
				{ID: CRC_32B, Hashcat: "", John: "", Extended: false},
				{ID: FCS_32, Hashcat: "", John: "", Extended: false},
				{ID: GHash_32_3, Hashcat: "", John: "", Extended: false},
				{ID: GHash_32_5, Hashcat: "", John: "", Extended: false},
				{ID: FNV_132, Hashcat: "", John: "", Extended: false},
				{ID: Fletcher_32, Hashcat: "", John: "", Extended: false},
				{ID: Joaat, Hashcat: "", John: "", Extended: false},
				{ID: ELF_32, Hashcat: "", John: "", Extended: false},
				{ID: XOR_32, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{6}$"),
			[]HashInfo{
				{ID: CRC_24, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$crc32\\$[a-f0-9]{8}.)?[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: CRC_32, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\+[a-z0-9\\/.]{12}$"),
			[]HashInfo{
				{ID: Eggdrop_IRC_Bot, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/.]{13}$"),
			[]HashInfo{
				{ID: DES_Unix, Hashcat: "1500", John: "1500", Extended: false},
				{ID: Traditional_DES, Hashcat: "1500", John: "1500", Extended: false},
				{ID: DEScrypt, Hashcat: "1500", John: "1500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{16}$"),
			[]HashInfo{
				{ID: MySQL323, Hashcat: "200", John: "200", Extended: false},
				{ID: DES_Oracle, Hashcat: "3100", John: "3100", Extended: false},
				{ID: Half_MD5, Hashcat: "5100", John: "5100", Extended: false},
				{ID: Oracle_7_10g, Hashcat: "3100", John: "3100", Extended: false},
				{ID: FNV_164, Hashcat: "", John: "", Extended: false},
				{ID: CRC_64, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/.]{16}$"),
			[]HashInfo{
				{ID: Cisco_PIX_MD5, Hashcat: "2400", John: "2400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\([a-z0-9\\/+]{20}\\)$"),
			[]HashInfo{
				{ID: Lotus_Notes_Domino_6, Hashcat: "8700", John: "8700", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^_[a-z0-9\\/.]{19}$"),
			[]HashInfo{
				{ID: BSDi_Crypt, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{24}$"),
			[]HashInfo{
				{ID: CRC_96_ZIP, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/.]{24}$"),
			[]HashInfo{
				{ID: Crypt16, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$md2\\$)?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: MD2, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}(:.+)?$"),
			[]HashInfo{
				{ID: MD5, Hashcat: "0", John: "0", Extended: false},
				{ID: MD4, Hashcat: "900", John: "900", Extended: false},
				{ID: Double_MD5, Hashcat: "2600", John: "2600", Extended: false},
				{ID: LM, Hashcat: "3000", John: "3000", Extended: false},
				{ID: RIPEMD_128, Hashcat: "", John: "", Extended: false},
				{ID: Haval_128, Hashcat: "", John: "", Extended: false},
				{ID: Tiger_128, Hashcat: "", John: "", Extended: false},
				{ID: Skein_256_128, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512_128, Hashcat: "", John: "", Extended: false},
				{ID: Lotus_Notes_Domino_5, Hashcat: "8600", John: "8600", Extended: false},
				{ID: Skype, Hashcat: "23", John: "23", Extended: false},
				{ID: ZipMonster, Hashcat: "", John: "", Extended: true},
				{ID: PrestaShop, Hashcat: "11000", John: "11000", Extended: true},
				{ID: Md5_md5_md5_pass, Hashcat: "3500", John: "3500", Extended: true},
				{ID: Md5_strtoupper_md5_pass, Hashcat: "4300", John: "4300", Extended: true},
				{ID: Md5_sha1_pass, Hashcat: "4400", John: "4400", Extended: true},
				{ID: Md5_pass_salt, Hashcat: "10", John: "10", Extended: true},
				{ID: Md5_salt_pass, Hashcat: "20", John: "20", Extended: true},
				{ID: Md5_unicode_pass_salt, Hashcat: "30", John: "30", Extended: true},
				{ID: Md5_salt_unicode_pass, Hashcat: "40", John: "40", Extended: true},
				{ID: HMAC_MD5_key_pass, Hashcat: "50", John: "50", Extended: true},
				{ID: HMAC_MD5_key_salt, Hashcat: "60", John: "60", Extended: true},
				{ID: Md5_md5_salt_pass, Hashcat: "3610", John: "3610", Extended: true},
				{ID: Md5_salt_md5_pass, Hashcat: "3710", John: "3710", Extended: true},
				{ID: Md5_pass_md5_salt, Hashcat: "3720", John: "3720", Extended: true},
				{ID: Md5_salt_pass_salt, Hashcat: "3810", John: "3810", Extended: true},
				{ID: Md5_md5_pass_md5_salt, Hashcat: "3910", John: "3910", Extended: true},
				{ID: Md5_salt_md5_salt_pass, Hashcat: "4010", John: "4010", Extended: true},
				{ID: Md5_salt_md5_pass_salt, Hashcat: "4110", John: "4110", Extended: true},
				{ID: Md5_username_0_pass, Hashcat: "4210", John: "4210", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$snefru\\$)?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: Snefru_128, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$NT\\$)?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: NTLM, Hashcat: "1000", John: "1000", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^([^\\/:*?\"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\/:*?\"<>|]{1,20})?$"),
			[]HashInfo{
				{ID: Domain_Cached_Credentials, Hashcat: "1100", John: "1100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^([^\\/:*?\"<>|]{1,20}:)?(\\$DCC2\\$10240#[^\\/:*?\"<>|]{1,20}#)?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: Domain_Cached_Credentials_2, Hashcat: "2100", John: "2100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{SHA}[a-z0-9\\/+]{27}=$"),
			[]HashInfo{
				{ID: SHA_1_Base64, Hashcat: "101", John: "101", Extended: false},
				{ID: Netscape_LDAP_SHA, Hashcat: "101", John: "101", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}(:.*)?$"),
			[]HashInfo{
				{ID: MD5_Crypt, Hashcat: "500", John: "500", Extended: false},
				{ID: Cisco_IOS_MD5, Hashcat: "500", John: "500", Extended: false},
				{ID: FreeBSD_MD5, Hashcat: "500", John: "500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: Lineage_II_C4, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$H\\$[a-z0-9\\/.]{31}$"),
			[]HashInfo{
				{ID: PhpBB_v3_x, Hashcat: "400", John: "400", Extended: false},
				{ID: Wordpress_v2_6_0_2_6_1, Hashcat: "400", John: "400", Extended: false},
				{ID: PHPass_Portable_Hash, Hashcat: "400", John: "400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$P\\$[a-z0-9\\/.]{31}$"),
			[]HashInfo{
				{ID: Wordpress_v2_6_2, Hashcat: "400", John: "400", Extended: false},
				{ID: Joomla_v2_5_18, Hashcat: "400", John: "400", Extended: false},
				{ID: PHPass_Portable_Hash, Hashcat: "400", John: "400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:[a-z0-9]{2}$"),
			[]HashInfo{
				{ID: OsCommerce, Hashcat: "21", John: "21", Extended: false},
				{ID: Xt_Commerce, Hashcat: "21", John: "21", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$apr1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}$"),
			[]HashInfo{
				{ID: MD5_APR, Hashcat: "1600", John: "1600", Extended: false},
				{ID: Apache_MD5, Hashcat: "1600", John: "1600", Extended: false},
				{ID: Md5apr1, Hashcat: "1600", John: "1600", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^{smd5}[a-z0-9$\\/.]{31}$"),
			[]HashInfo{
				{ID: AIX_smd5, Hashcat: "6300", John: "6300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: WebEdition_CMS, Hashcat: "3721", John: "3721", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:.{5}$"),
			[]HashInfo{
				{ID: IP_Board_v2, Hashcat: "2811", John: "2811", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:.{8}$"),
			[]HashInfo{
				{ID: MyBB_v1_2, Hashcat: "2811", John: "2811", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9]{34}$"),
			[]HashInfo{
				{ID: CryptoCurrency_Adress, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{40}(:.+)?$"),
			[]HashInfo{
				{ID: SHA_1, Hashcat: "100", John: "100", Extended: false},
				{ID: Double_SHA_1, Hashcat: "4500", John: "4500", Extended: false},
				{ID: RIPEMD_160, Hashcat: "6000", John: "6000", Extended: false},
				{ID: Haval_160, Hashcat: "", John: "", Extended: false},
				{ID: Tiger_160, Hashcat: "", John: "", Extended: false},
				{ID: HAS_160, Hashcat: "", John: "", Extended: false},
				{ID: LinkedIn, Hashcat: "190", John: "190", Extended: false},
				{ID: Skein_256_160, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512_160, Hashcat: "", John: "", Extended: false},
				{ID: MangosWeb_Enhanced_CMS, Hashcat: "", John: "", Extended: true},
				{ID: Sha1_sha1_sha1_pass, Hashcat: "4600", John: "4600", Extended: true},
				{ID: Sha1_md5_pass, Hashcat: "4700", John: "4700", Extended: true},
				{ID: Sha1_pass_salt, Hashcat: "110", John: "110", Extended: true},
				{ID: Sha1_salt_pass, Hashcat: "120", John: "120", Extended: true},
				{ID: Sha1_unicode_pass_salt, Hashcat: "130", John: "130", Extended: true},
				{ID: Sha1_salt_unicode_pass, Hashcat: "140", John: "140", Extended: true},
				{ID: HMAC_SHA1_key_pass, Hashcat: "150", John: "150", Extended: true},
				{ID: HMAC_SHA1_key_salt, Hashcat: "160", John: "160", Extended: true},
				{ID: Sha1_salt_pass_salt, Hashcat: "4710", John: "4710", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^\\*[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: MySQL5_x, Hashcat: "300", John: "300", Extended: false},
				{ID: MySQL4_1, Hashcat: "300", John: "300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9]{43}$"),
			[]HashInfo{
				{ID: Cisco_IOS_SHA_256, Hashcat: "5700", John: "5700", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{SSHA}[a-z0-9\\/+]{38}==$"),
			[]HashInfo{
				{ID: SSHA_1_Base64, Hashcat: "111", John: "111", Extended: false},
				{ID: Netscape_LDAP_SSHA, Hashcat: "111", John: "111", Extended: false},
				{ID: Nsldaps, Hashcat: "111", John: "111", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9=]{47}$"),
			[]HashInfo{
				{ID: Fortigate_FortiOS, Hashcat: "7000", John: "7000", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{48}$"),
			[]HashInfo{
				{ID: Haval_192, Hashcat: "", John: "", Extended: false},
				{ID: Tiger_192, Hashcat: "", John: "", Extended: false},
				{ID: SHA_1_Oracle, Hashcat: "", John: "", Extended: false},
				{ID: OSX_v10_4, Hashcat: "122", John: "122", Extended: false},
				{ID: OSX_v10_5, Hashcat: "122", John: "122", Extended: false},
				{ID: OSX_v10_6, Hashcat: "122", John: "122", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{51}$"),
			[]HashInfo{
				{ID: Palshop_CMS, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9]{51}$"),
			[]HashInfo{
				{ID: CryptoCurrency_PrivateKey, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{ssha1}[0-9]{2}\\$[a-z0-9$\\/.]{44}$"),
			[]HashInfo{
				{ID: AIX_ssha1, Hashcat: "6700", John: "6700", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x0100[a-f0-9]{48}$"),
			[]HashInfo{
				{ID: MSSQL_2005, Hashcat: "132", John: "132", Extended: false},
				{ID: MSSQL_2008, Hashcat: "132", John: "132", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$md5,rounds=[0-9]+\\$|\\$md5\\$rounds=[0-9]+\\$|\\$md5\\$)[a-z0-9\\/.]{0,16}(\\$|\\$\\$)[a-z0-9\\/.]{22}$"),
			[]HashInfo{
				{ID: Sun_MD5_Crypt, Hashcat: "3300", John: "3300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{56}$"),
			[]HashInfo{
				{ID: SHA_224, Hashcat: "", John: "", Extended: false},
				{ID: Haval_224, Hashcat: "", John: "", Extended: false},
				{ID: SHA3_224, Hashcat: "", John: "", Extended: false},
				{ID: Skein_256_224, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512_224, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$"),
			[]HashInfo{
				{ID: Blowfish_OpenBSD, Hashcat: "3200", John: "3200", Extended: false},
				{ID: Woltlab_Burning_Board_4_x, Hashcat: "", John: "", Extended: false},
				{ID: Bcrypt, Hashcat: "3200", John: "3200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{40}:[a-f0-9]{16}$"),
			[]HashInfo{
				{ID: Android_PIN, Hashcat: "5800", John: "5800", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$"),
			[]HashInfo{
				{ID: Oracle_11g_12c, Hashcat: "112", John: "112", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$bcrypt-sha256\\$(2[axy]|2)\\,[0-9]+\\$[a-z0-9\\/.]{22}\\$[a-z0-9\\/.]{31}$"),
			[]HashInfo{
				{ID: Bcrypt_SHA_256, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:.{3}$"),
			[]HashInfo{
				{ID: VBulletin_v3_8_5, Hashcat: "2611", John: "2611", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:.{30}$"),
			[]HashInfo{
				{ID: VBulletin_v3_8_5, Hashcat: "2711", John: "2711", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$snefru\\$)?[a-f0-9]{64}$"),
			[]HashInfo{
				{ID: Snefru_256, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{64}(:.+)?$"),
			[]HashInfo{
				{ID: SHA_256, Hashcat: "1400", John: "1400", Extended: false},
				{ID: RIPEMD_256, Hashcat: "", John: "", Extended: false},
				{ID: Haval_256, Hashcat: "", John: "", Extended: false},
				{ID: GOST_R_34_11_94, Hashcat: "6900", John: "6900", Extended: false},
				{ID: GOST_CryptoPro_S_Box, Hashcat: "", John: "", Extended: false},
				{ID: SHA3_256, Hashcat: "5000", John: "5000", Extended: false},
				{ID: Skein_256, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512_256, Hashcat: "", John: "", Extended: false},
				{ID: Ventrilo, Hashcat: "", John: "", Extended: true},
				{ID: Sha256_pass_salt, Hashcat: "1410", John: "1410", Extended: true},
				{ID: Sha256_salt_pass, Hashcat: "1420", John: "1420", Extended: true},
				{ID: Sha256_unicode_pass_salt, Hashcat: "1430", John: "1430", Extended: true},
				{ID: Sha256_salt_unicode_pass, Hashcat: "1440", John: "1440", Extended: true},
				{ID: HMAC_SHA256_key_pass, Hashcat: "1450", John: "1450", Extended: true},
				{ID: HMAC_SHA256_key_salt, Hashcat: "1460", John: "1460", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:[a-z0-9]{32}$"),
			[]HashInfo{
				{ID: Joomla_v2_5_18, Hashcat: "11", John: "11", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f-0-9]{32}:[a-f-0-9]{32}$"),
			[]HashInfo{
				{ID: SAM_LM_Hash_NT_Hash, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$chap\\$0\\*)?[a-f0-9]{32}[\\*:][a-f0-9]{32}(:[0-9]{2})?$"),
			[]HashInfo{
				{ID: MD5_Chap, Hashcat: "4800", John: "4800", Extended: false},
				{ID: ISCSI_CHAP_Authentication, Hashcat: "4800", John: "4800", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$episerver\\$\\*0\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{27,28}$"),
			[]HashInfo{
				{ID: EPiServer_6_x_v4, Hashcat: "141", John: "141", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{ssha256}[0-9]{2}\\$[a-z0-9$\\/.]{60}$"),
			[]HashInfo{
				{ID: AIX_ssha256, Hashcat: "6400", John: "6400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{80}$"),
			[]HashInfo{
				{ID: RIPEMD_320, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$episerver\\$\\*1\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{42,43}$"),
			[]HashInfo{
				{ID: EPiServer_6_x_v4, Hashcat: "1441", John: "1441", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x0100[a-f0-9]{88}$"),
			[]HashInfo{
				{ID: MSSQL_2000, Hashcat: "131", John: "131", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{96}$"),
			[]HashInfo{
				{ID: SHA_384, Hashcat: "10800", John: "10800", Extended: false},
				{ID: SHA3_384, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512_384, Hashcat: "", John: "", Extended: false},
				{ID: Skein_1024_384, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{SSHA512}[a-z0-9\\/+]{96}$"),
			[]HashInfo{
				{ID: SSHA_512_Base64, Hashcat: "1711", John: "1711", Extended: false},
				{ID: LDAP_SSHA_512, Hashcat: "1711", John: "1711", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{ssha512}[0-9]{2}\\$[a-z0-9\\/.]{16,48}\\$[a-z0-9\\/.]{86}$"),
			[]HashInfo{
				{ID: AIX_ssha512, Hashcat: "6500", John: "6500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{128}(:.+)?$"),
			[]HashInfo{
				{ID: SHA_512, Hashcat: "1700", John: "1700", Extended: false},
				{ID: Whirlpool, Hashcat: "6100", John: "6100", Extended: false},
				{ID: Salsa10, Hashcat: "", John: "", Extended: false},
				{ID: Salsa20, Hashcat: "", John: "", Extended: false},
				{ID: SHA3_512, Hashcat: "", John: "", Extended: false},
				{ID: Skein_512, Hashcat: "", John: "", Extended: false},
				{ID: Skein_1024_512, Hashcat: "", John: "", Extended: false},
				{ID: Sha512_pass_salt, Hashcat: "1710", John: "1710", Extended: true},
				{ID: Sha512_salt_pass, Hashcat: "1720", John: "1720", Extended: true},
				{ID: Sha512_unicode_pass_salt, Hashcat: "1730", John: "1730", Extended: true},
				{ID: Sha512_salt_unicode_pass, Hashcat: "1740", John: "1740", Extended: true},
				{ID: HMAC_SHA512_key_pass, Hashcat: "1750", John: "1750", Extended: true},
				{ID: HMAC_SHA512_key_salt, Hashcat: "1760", John: "1760", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{136}$"),
			[]HashInfo{
				{ID: OSX_v10_7, Hashcat: "1722", John: "1722", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x0200[a-f0-9]{136}$"),
			[]HashInfo{
				{ID: MSSQL_2012, Hashcat: "1731", John: "1731", Extended: false},
				{ID: MSSQL_2014, Hashcat: "1731", John: "1731", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$ml\\$[0-9]+\\$[a-f0-9]{64}\\$[a-f0-9]{128}$"),
			[]HashInfo{
				{ID: OSX_v10_8, Hashcat: "7100", John: "7100", Extended: false},
				{ID: OSX_v10_9, Hashcat: "7100", John: "7100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{256}$"),
			[]HashInfo{
				{ID: Skein_1024, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^grub\\.pbkdf2\\.sha512\\.[0-9]+\\.([a-f0-9]{128:}\\.|[0-9]+\\.)?[a-f0-9]{128}$"),
			[]HashInfo{
				{ID: GRUB_2, Hashcat: "7200", John: "7200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^sha1\\$[a-z0-9]+\\$[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: Django_SHA_1, Hashcat: "124", John: "124", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{49}$"),
			[]HashInfo{
				{ID: Citrix_Netscaler, Hashcat: "8100", John: "8100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$S\\$[a-z0-9\\/.]{52}$"),
			[]HashInfo{
				{ID: Drupal_v7_x, Hashcat: "7900", John: "7900", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$5\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{43}$"),
			[]HashInfo{
				{ID: SHA_256_Crypt, Hashcat: "7400", John: "7400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$"),
			[]HashInfo{
				{ID: Sybase_ASE, Hashcat: "8000", John: "8000", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$6\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{86}$"),
			[]HashInfo{
				{ID: SHA_512_Crypt, Hashcat: "1800", John: "1800", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$sha\\$[a-z0-9]{1,16}\\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$"),
			[]HashInfo{
				{ID: Minecraft_AuthMe_Reloaded, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^sha256\\$[a-z0-9]+\\$[a-f0-9]{64}$"),
			[]HashInfo{
				{ID: Django_SHA_256, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^sha384\\$[a-z0-9]+\\$[a-f0-9]{96}$"),
			[]HashInfo{
				{ID: Django_SHA_384, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$"),
			[]HashInfo{
				{ID: Clavister_Secure_Gateway, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{112}$"),
			[]HashInfo{
				{ID: Cisco_VPN_Client_PCF_File, Hashcat: "", John: "", Extended: false},
			},
		},
		// {
		// 	regexp.MustCompile("(?i)^[a-f0-9]{1329}$"),
		// 	[]HashInfo{
		// 		{ID: Microsoft_MSTSC_RDP_File, Hashcat: "", John: "", Extended: false},
		// 	},
		// },
		{
			regexp.MustCompile("(?i)^[^\\/:*?\"<>|]{1,20}[:]{2,3}([^\\/:*?\"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$"),
			[]HashInfo{
				{ID: NetNTLMv1_VANILLA_NetNTLMv1_ESS, Hashcat: "5500", John: "5500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^([^\\/:*?\"<>|]{1,20})?[^\\/:*?\"<>|]{1,20}[:]{2,3}([^\\/:*?\"<>|]{1,20}:)?[^\\/:*?\"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$"),
			[]HashInfo{
				{ID: NetNTLMv2, Hashcat: "5600", John: "5600", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$(krb5pa|mskrb5)\\$([0-9]{2})?\\$.+\\$[a-f0-9]{1,}$"),
			[]HashInfo{
				{ID: Kerberos_5_AS_REQ_Pre_Auth, Hashcat: "7500", John: "7500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$scram\\$[0-9]+\\$[a-z0-9\\/.]{16}\\$sha-1=[a-z0-9\\/.]{27},sha-256=[a-z0-9\\/.]{43},sha-512=[a-z0-9\\/.]{86}$"),
			[]HashInfo{
				{ID: SCRAM_Hash, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{40}:[a-f0-9]{0,32}$"),
			[]HashInfo{
				{ID: Redmine_Project_Management_Web_App, Hashcat: "7600", John: "7600", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(.+)?\\$[a-f0-9]{16}$"),
			[]HashInfo{
				{ID: SAP_CODVN_B_BCODE, Hashcat: "7700", John: "7700", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(.+)?\\$[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: SAP_CODVN_F_G_PASSCODE, Hashcat: "7800", John: "7800", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(.+\\$)?[a-z0-9\\/.+]{30}(:.+)?$"),
			[]HashInfo{
				{ID: Juniper_Netscreen_SSG_ScreenOS, Hashcat: "22", John: "22", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^0x[a-f0-9]{60}\\s0x[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: EPi, Hashcat: "123", John: "123", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{40}:[^*]{1,25}$"),
			[]HashInfo{
				{ID: SMF_v1_1, Hashcat: "121", John: "121", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$wbb3\\$\\*1\\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$"),
			[]HashInfo{
				{ID: Woltlab_Burning_Board_3_x, Hashcat: "8400", John: "8400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{130}(:[a-f0-9]{40})?$"),
			[]HashInfo{
				{ID: IPMI2_RAKP_HMAC_SHA1, Hashcat: "7300", John: "7300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9-.]+$"),
			[]HashInfo{
				{ID: Lastpass, Hashcat: "6800", John: "6800", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/.]{16}([:$].{1,})?$"),
			[]HashInfo{
				{ID: Cisco_ASA_MD5, Hashcat: "2410", John: "2410", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$vnc\\$\\*[a-f0-9]{32}\\*[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: VNC, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9]{32}(:([a-z0-9-]+\\.)?[a-z0-9-.]+\\.[a-z]{2,7}:.+:[0-9]+)?$"),
			[]HashInfo{
				{ID: DNSSEC_NSEC3, Hashcat: "8300", John: "8300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(user-.+:)?\\$racf\\$\\*.+\\*[a-f0-9]{16}$"),
			[]HashInfo{
				{ID: RACF, Hashcat: "8500", John: "8500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$3\\$\\$[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: NTHash_FreeBSD_Variant, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$sha1\\$[0-9]+\\$[a-z0-9\\/.]{0,64}\\$[a-z0-9\\/.]{28}$"),
			[]HashInfo{
				{ID: SHA_1_Crypt, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{70}$"),
			[]HashInfo{
				{ID: HMailServer, Hashcat: "1421", John: "1421", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[:\\$][AB][:\\$]([a-f0-9]{1,8}[:\\$])?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: MediaWiki, Hashcat: "3711", John: "3711", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{140}$"),
			[]HashInfo{
				{ID: Minecraft_xAuth, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$pbkdf2(-sha1)?\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{27}$"),
			[]HashInfo{
				{ID: PBKDF2_SHA1_Generic, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$pbkdf2-sha256\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{43}$"),
			[]HashInfo{
				{ID: PBKDF2_SHA256_Generic, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$pbkdf2-sha512\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{86}$"),
			[]HashInfo{
				{ID: PBKDF2_SHA512_Generic, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+-]{27}=$"),
			[]HashInfo{
				{ID: PBKDF2_Cryptacular, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{32}$"),
			[]HashInfo{
				{ID: PBKDF2_Dwayne_Litzenberger, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{FSHP[0123]\\|[0-9]+\\|[0-9]+}[a-z0-9\\/+=]+$"),
			[]HashInfo{
				{ID: Fairly_Secure_Hashed_Password, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$PHPS\\$.+\\$[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: PHPS, Hashcat: "2612", John: "2612", Extended: false},
			},
		},
		// {
		// 	regexp.MustCompile("(?i)^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$"),
		// 	[]HashInfo{
		// 		{ID: OnePassword_Agile_Keychain, Hashcat: "6600", John: "6600", Extended: false},
		// 	},
		// },
		{
			regexp.MustCompile("(?i)^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$"),
			[]HashInfo{
				{ID: OnePassword_Cloud_Keychain, Hashcat: "8200", John: "8200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: IKE_PSK_MD5, Hashcat: "5300", John: "5300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: IKE_PSK_SHA1, Hashcat: "5400", John: "5400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/+]{27}=$"),
			[]HashInfo{
				{ID: PeopleSoft, Hashcat: "133", John: "133", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^crypt\\$[a-f0-9]{5}\\$[a-z0-9\\/.]{13}$"),
			[]HashInfo{
				{ID: Django_DES_Crypt_Wrapper, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$django\\$\\*1\\*)?pbkdf2_sha256\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{44}$"),
			[]HashInfo{
				{ID: Django_PBKDF2_HMAC_SHA256, Hashcat: "10000", John: "10000", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^pbkdf2_sha1\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{28}$"),
			[]HashInfo{
				{ID: Django_PBKDF2_HMAC_SHA1, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^bcrypt(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$"),
			[]HashInfo{
				{ID: Django_bcrypt, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^md5\\$[a-f0-9]+\\$[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: Django_MD5, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\{PKCS5S2\\}[a-z0-9\\/+]{64}$"),
			[]HashInfo{
				{ID: PBKDF2_Atlassian, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^md5[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: PostgreSQL_MD5, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\([a-z0-9\\/+]{49}\\)$"),
			[]HashInfo{
				{ID: Lotus_Notes_Domino_8, Hashcat: "9100", John: "9100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\\/+=]{1,}$"),
			[]HashInfo{
				{ID: Scrypt, Hashcat: "8900", John: "8900", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$8\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$"),
			[]HashInfo{
				{ID: Cisco_Type_8, Hashcat: "9200", John: "9200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$9\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$"),
			[]HashInfo{
				{ID: Cisco_Type_9, Hashcat: "9300", John: "9300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$office\\$\\*2007\\*[0-9]{2}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{40}$"),
			[]HashInfo{
				{ID: Microsoft_Office_2007, Hashcat: "9400", John: "9400", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$office\\$\\*2010\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$"),
			[]HashInfo{
				{ID: Microsoft_Office_2010, Hashcat: "9500", John: "9500", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$office\\$\\*2013\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$"),
			[]HashInfo{
				{ID: Microsoft_Office_2013, Hashcat: "9600", John: "9600", Extended: false},
			},
		},
		// {
		// 	regexp.MustCompile("(?i)^\\$fde\\$[0-9]{2}\\$[a-f0-9]{32}\\$[0-9]{2}\\$[a-f0-9]{32}\\$[a-f0-9]{3072}$"),
		// 	[]HashInfo{
		// 		{ID: Android_FDE_4_3, Hashcat: "8800", John: "8800", Extended: false},
		// 	},
		// },
		{
			regexp.MustCompile("(?i)^\\$oldoffice\\$[01]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: Microsoft_Office_2003_MD5_RC4, Hashcat: "9700", John: "9700", Extended: false},
				{ID: Microsoft_Office_2003_MD5_RC4_collider_mode_1, Hashcat: "9710", John: "9710", Extended: false},
				{ID: Microsoft_Office_2003_MD5_RC4_collider_mode_2, Hashcat: "9720", John: "9720", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$oldoffice\\$[34]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: Microsoft_Office_2003_SHA1_RC4, Hashcat: "9800", John: "9800", Extended: false},
				{ID: Microsoft_Office_2003_SHA1_RC4_collider_mode_1, Hashcat: "9810", John: "9810", Extended: false},
				{ID: Microsoft_Office_2003_SHA1_RC4_collider_mode_2, Hashcat: "9820", John: "9820", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$radmin2\\$)?[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: RAdmin_v2_x, Hashcat: "9900", John: "9900", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^{x-issha,\\s[0-9]{4}}[a-z0-9\\/+=]+$"),
			[]HashInfo{
				{ID: SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1, Hashcat: "10300", John: "10300", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$cram_md5\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+=-]{52}$"),
			[]HashInfo{
				{ID: CRAM_MD5, Hashcat: "10200", John: "10200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{16}:2:4:[a-f0-9]{32}$"),
			[]HashInfo{
				{ID: SipHash, Hashcat: "10100", John: "10100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{4,}$"),
			[]HashInfo{
				{ID: Cisco_Type_7, Hashcat: "", John: "", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-z0-9\\/.]{13,}$"),
			[]HashInfo{
				{ID: BigCrypt, Hashcat: "", John: "", Extended: true},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$cisco4\\$)?[a-z0-9\\/.]{43}$"),
			[]HashInfo{
				{ID: Cisco_Type_4, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^bcrypt_sha256\\$\\$(2[axy]|2)\\$[0-9]+\\$[a-z0-9\\/.]{53}$"),
			[]HashInfo{
				{ID: Django_bcrypt_SHA256, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$postgres\\$.[^\\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$"),
			[]HashInfo{
				{ID: PostgreSQL_Challenge_Response_Authentication_MD5, Hashcat: "11100", John: "11100", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$siemens-s7\\$\\$[0-9]{1}\\$[a-f0-9]{40}\\$[a-f0-9]{40}$"),
			[]HashInfo{
				{ID: Siemens_S7, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$pst\\$)?[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: Microsoft_Outlook_PST, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^sha256[:$][0-9]+[:$][a-z0-9\\/+]+[:$][a-z0-9\\/+]{32,128}$"),
			[]HashInfo{
				{ID: PBKDF2_HMAC_SHA256_PHP, Hashcat: "10900", John: "10900", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$dahua\\$)?[a-z0-9]{8}$"),
			[]HashInfo{
				{ID: Dahua, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$mysqlna\\$[a-f0-9]{40}[:*][a-f0-9]{40}$"),
			[]HashInfo{
				{ID: MySQL_Challenge_Response_Authentication_SHA1, Hashcat: "11200", John: "11200", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^\\$pdf\\$[24]\\*[34]\\*128\\*[0-9-]{1,5}\\*1\\*(16|32)\\*[a-f0-9]{32,64}\\*32\\*[a-f0-9]{64}\\*(8|16|32)\\*[a-f0-9]{16,64}$"),
			[]HashInfo{
				{ID: PDF_1_4_1_6_Acrobat_5_8, Hashcat: "10500", John: "10500", Extended: false},
			},
		},
	}
}

func Identify(hash []byte, pr []Prototype) ([]HashInfo, error) {
	var i, j int
	var result []HashInfo
	for i = range pr {
		if pr[i].Re.Match(hash) {
			for j = range pr[i].Modes {
				result = append(result, pr[i].Modes[j])
			}
		}
	}
	return result, nil
}
