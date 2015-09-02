#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

// https://github.com/iSECPartners/ssl-conservatory

static void dump_alt_names(const X509 *server_cert,int nid,const char *prefix) {
    int i=0;
    int san_names_nb = -1;
    STACK_OF(GENERAL_NAME) *san_names = NULL;

    // Try to extract the names within the SAN extension from the certificate
    san_names = X509_get_ext_d2i((X509 *) server_cert, nid, NULL, NULL);
    if (san_names == NULL) {
        return ;
    }
    san_names_nb = sk_GENERAL_NAME_num(san_names);

    // Check each name within the extension
    for (i=0; i<san_names_nb; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            // Current name is a DNS name, let's check it
            char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);

            // Make sure there isn't an embedded NUL character in the DNS name
            if (ASN1_STRING_length(current_name->d.dNSName) == strlen(dns_name)) {
                printf("%s%s\n",prefix,dns_name);
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
}


int main(int argc,const char **argv)
{
    const char *path = argv[1];
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "unable to open: %s\n", path);
        return EXIT_FAILURE;
    }
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "unable to parse certificate in: %s\n", path);
        fclose(fp);
        return EXIT_FAILURE;
    }
    
    dump_alt_names(cert,NID_dNSDomain,"");
    dump_alt_names(cert,NID_subject_alt_name,"");

    // any additional processing would go here..

    X509_free(cert);
    fclose(fp);
    return(0);
}

