from tpm2_pytss import *

parent_template = TPM2B_PUBLIC(
    publicArea=TPMT_PUBLIC(
        type=TPM2_ALG.RSA,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
                TPMA_OBJECT.RESTRICTED |
                TPMA_OBJECT.DECRYPT |
                TPMA_OBJECT.FIXEDTPM |
                TPMA_OBJECT.FIXEDPARENT |
                TPMA_OBJECT.SENSITIVEDATAORIGIN |
                TPMA_OBJECT.USERWITHAUTH
        ),
        parameters=TPMU_PUBLIC_PARMS(
            rsaDetail=TPMS_RSA_PARMS(
                symmetric=TPMT_SYM_DEF_OBJECT(
                    algorithm=TPM2_ALG.AES,
                    keyBits=TPMU_SYM_KEY_BITS(sym=128),
                    mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
                ),
                scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                keyBits=2048,
                exponent=0,
            )
        ),
        unique=TPMU_PUBLIC_ID(
            rsa=TPM2B_PUBLIC_KEY_RSA(buffer=b'\x00' * 256)
        )
    )
)

child_template = TPM2B_PUBLIC(
    publicArea=TPMT_PUBLIC(
        type=TPM2_ALG.RSA,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
                TPMA_OBJECT.SIGN_ENCRYPT |
                TPMA_OBJECT.USERWITHAUTH |
                TPMA_OBJECT.DECRYPT |
                TPMA_OBJECT.FIXEDTPM |
                TPMA_OBJECT.FIXEDPARENT |
                TPMA_OBJECT.SENSITIVEDATAORIGIN
        ),
        parameters=TPMU_PUBLIC_PARMS(
            rsaDetail=TPMS_RSA_PARMS(
                symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
                scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                keyBits=2048,
                exponent=0,
            )
        ),
        unique=TPMU_PUBLIC_ID(
            rsa=TPM2B_PUBLIC_KEY_RSA(buffer=b'\x00' * 256)
        )
    )
)