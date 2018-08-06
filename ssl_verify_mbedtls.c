#include <rain_common.h>

#ifdef MBEDTLS_CONF


int verify_callback (void *epd_obj, mbedtls_x509_crt *cert, int cert_depth,int *flags)
{

	struct epoll_ptr_data *epd = (struct epoll_ptr_data *)epd_obj;
	assert (cert);

	epd->ss->verified = false;

	unsigned char *hash = x509_get_sha1_hash(cert);
	cert_hash_remember (epd, cert_depth, hash);
	sfree(hash);
printf("################# %s %d #############\n",__func__,__LINE__);
	if (*flags != 0)
	{
printf("################# %s %d #############\n",__func__,__LINE__);
		char * subject = NULL;

		subject = x509_get_subject(cert);

		if (subject != NULL ){
			MM("## %s %d : VERIFY ERROR: depth=%d, flags=%x, %s\n",__func__,__LINE__,cert_depth, *flags, subject);
		}else{
			MM("## %s %d : VERIFY ERROR: depth=%d, flags=%x, could not extract X509 subject string from certificate\n",__func__,__LINE__, *flags, cert_depth);
		}

		if(subject != NULL){
			sfree(subject);
		}

	}
	else if (SUCCESS != verify_cert(epd, cert, cert_depth))
	{
		*flags |= MBEDTLS_X509_BADCERT_OTHER;
	}

	return 0;
}

bool x509_get_username (char *cn, int cn_len,char *x509_username_field, mbedtls_x509_crt *cert)
{
	mbedtls_x509_name *name;

	assert( cn != NULL );

	if(x509_username_field){}

	name = &cert->subject;
	while( name != NULL )
	{
		if( memcmp( name->oid.p, MBEDTLS_OID_AT_CN , MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN) ) == 0){
			break;
		}

		name = name->next;
	}

	if( name == NULL ){
		MM("########### %s %d  ##\n",__func__,__LINE__);
		exit(0);
		return false;
	}

	if (cn_len > (int)name->val.len){
		memcpy(cn, name->val.p, name->val.len );
	}else
	{
		memcpy(cn, name->val.p, cn_len);
		cn[cn_len-1] = '\0';
	}

	return true;
}
#if 0
char * backend_x509_get_serial (openvpn_x509_cert_t *cert)
{
	char *buf = NULL;
	size_t buflen = 0;
	mbedtls_mpi serial_mpi = { 0 };

	mbedtls_mpi_init(&serial_mpi);
	//if (!polar_ok(mpi_read_binary(&serial_mpi, cert->serial.p, cert->serial.len)))
	if (mbedtls_mpi_read_binary(&serial_mpi, cert->serial.p, cert->serial.len) < 0)
	{
		MM("Failed to retrieve serial from certificate.\n");
		goto end;
	}

	mbedtls_mpi_write_string(&serial_mpi, 10, buf, &buflen);

	buf = malloc(buflen);
	memset(buf,0x00,buflen);

	/* Write MPI serial as decimal string into buffer */
	//if (!polar_ok(mpi_write_string(&serial_mpi, 10, buf, &buflen)))
	if (mbedtls_mpi_write_string(&serial_mpi, 10, buf, &buflen) < 0)
	{
		MM("Failed to write serial to string.\n");
		buf = NULL;
		goto end;
	}

end:
	mbedtls_mpi_free(&serial_mpi);
	return buf;
}
#endif

char * backend_x509_get_serial_hex (openvpn_x509_cert_t *cert)
{
	char *buf = NULL;
	size_t len = cert->serial.len * 3 + 1;

	buf = malloc(len);
	memset(buf,0x00,len);
	if(mbedtls_x509_serial_gets(buf, len-1, &cert->serial) < 0){
		buf = NULL;
	}
	return buf;
}

unsigned char * x509_get_sha1_hash (mbedtls_x509_crt *cert)
{
	unsigned char *sha1_hash = malloc(SHA_DIGEST_LENGTH);
	memset(sha1_hash,0x00,SHA_DIGEST_LENGTH);
	mbedtls_sha1(cert->tbs.p, cert->tbs.len, sha1_hash);
	return sha1_hash;
}

char * x509_get_subject(mbedtls_x509_crt *cert)
{
	char tmp_subject[MAX_SUBJECT_LENGTH] = {0,};
	char *subject = NULL;

	int ret = 0;

	ret = mbedtls_x509_dn_gets(tmp_subject, MAX_SUBJECT_LENGTH-1, &cert->subject );
	if (ret > 0)
	{
		subject = malloc(strlen(tmp_subject));
		memset(subject,0x00,strlen(tmp_subject));
		strncpy(subject,tmp_subject,strlen(tmp_subject));
	}

	return subject;
}
#if 0
void x509_setenv (struct env_set *es, int cert_depth, openvpn_x509_cert_t *cert)
{
	int i;
	unsigned char c;
	const x509_name *name;
	char s[128];

	name = &cert->subject;

	memset( s, 0, sizeof( s ) );

	while( name != NULL )
	{
		char name_expand[64+8];
		const char *shortname;

		if( 0 == oid_get_attr_short_name(&name->oid, &shortname) )
		{
			openvpn_snprintf (name_expand, sizeof(name_expand), "X509_%d_%s",
					cert_depth, shortname);
		}
		else
		{
			openvpn_snprintf (name_expand, sizeof(name_expand), "X509_%d_\?\?",
					cert_depth);
		}

		for( i = 0; i < name->val.len; i++ )
		{
			if( i >= (int) sizeof( s ) - 1 )
				break;

			c = name->val.p[i];
			if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
				s[i] = '?';
			else s[i] = c;
		}
		s[i] = '\0';

		/* Check both strings, set environment variable */
		string_mod (name_expand, CC_PRINT, CC_CRLF, '_');
		string_mod ((char*)s, CC_PRINT, CC_CRLF, '_');
		setenv_str (es, name_expand, (char*)s);

		name = name->next;
	}
}

result_t x509_verify_ns_cert_type(const x509_crt *cert, const int usage)
{
	if (usage == NS_CERT_CHECK_NONE)
		return SUCCESS;
	if (usage == NS_CERT_CHECK_CLIENT)
		return ((cert->ext_types & EXT_NS_CERT_TYPE)
				&& (cert->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT)) ? SUCCESS : FAILURE;
	if (usage == NS_CERT_CHECK_SERVER)
		return ((cert->ext_types & EXT_NS_CERT_TYPE)
				&& (cert->ns_cert_type & NS_CERT_TYPE_SSL_SERVER)) ? SUCCESS : FAILURE;

	return FAILURE;
}

result_t x509_verify_cert_ku (x509_crt *cert, const unsigned * const expected_ku,
		int expected_len)
{
	result_t fFound = FAILURE;

	if(!(cert->ext_types & EXT_KEY_USAGE))
	{
		msg (D_HANDSHAKE, "Certificate does not have key usage extension");
	}
	else
	{
		int i;
		unsigned nku = cert->key_usage;

		msg (D_HANDSHAKE, "Validating certificate key usage");
		for (i=0; SUCCESS != fFound && i<expected_len; i++)
		{
			if (expected_ku[i] != 0)
			{
				msg (D_HANDSHAKE, "++ Certificate has key usage  %04x, expects "
						"%04x", nku, expected_ku[i]);

				if (nku == expected_ku[i])
				{
					fFound = SUCCESS;
				}
			}
		}
	}
	return fFound;
}

result_t x509_verify_cert_eku (x509_crt *cert, const char * const expected_oid)
{
	result_t fFound = FAILURE;

	if (!(cert->ext_types & EXT_EXTENDED_KEY_USAGE))
	{
		msg (D_HANDSHAKE, "Certificate does not have extended key usage extension");
	}
	else
	{
		x509_sequence *oid_seq = &(cert->ext_key_usage);

		msg (D_HANDSHAKE, "Validating certificate extended key usage");
		while (oid_seq != NULL)
		{
			x509_buf *oid = &oid_seq->buf;
			char oid_num_str[1024];
			const char *oid_str;

			if (0 == oid_get_extended_key_usage( oid, &oid_str ))
			{
				msg (D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
						oid_str, expected_oid);
				if (!strcmp (expected_oid, oid_str))
				{
					fFound = SUCCESS;
					break;
				}
			}

			if (0 < oid_get_numeric_string( oid_num_str,
						sizeof (oid_num_str), oid))
			{
				msg (D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
						oid_num_str, expected_oid);
				if (!strcmp (expected_oid, oid_num_str))
				{
					fFound = SUCCESS;
					break;
				}
			}
			oid_seq = oid_seq->next;
		}
	}

	return fFound;
}

result_t x509_write_pem(FILE *peercert_file, x509_crt *peercert)
{
	msg (M_WARN, "PolarSSL does not support writing peer certificate in PEM format");
	return FAILURE;
}
result_t x509_verify_crl(const char *crl_file, x509_crt *cert, const char *subject)
{
	result_t retval = FAILURE;
	x509_crl crl = {0};
	struct gc_arena gc = gc_new();
	char *serial;

	//if (!polar_ok(x509_crl_parse_file(&crl, crl_file)))
	if (x509_crl_parse_file(&crl, crl_file) < 0)
	{
		msg (M_WARN, "CRL: cannot read CRL from file %s", crl_file);
		goto end;
	}

	if(cert->issuer_raw.len != crl.issuer_raw.len ||
			memcmp(crl.issuer_raw.p, cert->issuer_raw.p, crl.issuer_raw.len) != 0)
	{
		msg (M_WARN, "CRL: CRL %s is from a different issuer than the issuer of "
				"certificate %s", crl_file, subject);
		retval = SUCCESS;
		goto end;
	}

	//if (!polar_ok(x509_crt_revoked(cert, &crl)))
	if (x509_crt_revoked(cert, &crl) < 0)
	{
		serial = backend_x509_get_serial_hex(cert, &gc);
		msg (D_HANDSHAKE, "CRL CHECK FAILED: %s (serial %s) is REVOKED", subject, (serial ? serial : "NOT AVAILABLE"));
		goto end;
	}

	retval = SUCCESS;
	msg (D_HANDSHAKE, "CRL CHECK OK: %s",subject);

end:
	gc_free(&gc);
	x509_crl_free(&crl);
	return retval;
}
#endif
#endif
