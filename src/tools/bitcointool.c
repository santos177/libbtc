/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include "libbtc-config.h"

#include <btc/bip32.h>
#include <btc/chainparams.h>
#include <btc/ecc.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/tool.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static struct option long_options[] =
    {
        {"privkey", required_argument, NULL, 'p'},
        {"pubkey", required_argument, NULL, 'k'},
        {"keypath", required_argument, NULL, 'm'},
        {"command", required_argument, NULL, 'c'},
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'v'},
        {"txhex", no_argument, NULL, 'x'},
        {"scripthex", no_argument, NULL, 's'},
        {"inputindex", no_argument, NULL, 'i'},
        {"sighashtype", no_argument, NULL, 'h'},
        {"amount", no_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}};

static void print_version()
{
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage()
{
    print_version();
    printf("Usage: bitcointool (-m|-keypath <bip_keypath>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-t[--testnet]) (-r[--regtest]) -c <command>\n");
    printf("Available commands: pubfrompriv (requires -p WIF), addrfrompub (requires -k HEX), genkey, crack, hdgenmaster, hdprintkey (requires -p), hdderive (requires -m and -p) \n");
    printf("\nExamples: \n");
    printf("Generate a testnet privatekey in WIF/HEX format:\n");
    printf("> bitcointool -c genkey --testnet\n\n");
    printf("> bitcointool -c pubfrompriv -p KzLzeMteBxy8aPPDCeroWdkYPctafGapqBAmWQwdvCkgKniH9zw6\n\n");
}

static bool showError(const char* er)
{
    printf("Error: %s\n", er);
    btc_ecc_stop();
    return 1;
}

int main(int argc, char* argv[])
{
    int long_index = 0;
    int opt = 0;
    char* pkey      = 0;
    char* pubkey    = 0;
    char* cmd       = 0;
    char* keypath   = 0;
    char* txhex     = 0;
    char* scripthex = 0;
    int inputindex  = 0;
    int sighashtype = 1;
    uint64_t amount = 0;
    const btc_chainparams* chain = &btc_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "h:i:s:x:p:k:a:m:c:trv", long_options, &long_index)) != -1) {
        switch (opt) {
        case 'p':
            pkey = optarg;
            if (strlen(pkey) < 50)
                return showError("Private key must be WIF encoded");
            break;
        case 'c':
            cmd = optarg;
            break;
        case 'm':
            keypath = optarg;
            break;
        case 'k':
            pubkey = optarg;
            break;
        case 't':
            chain = &btc_chainparams_test;
            break;
        case 'r':
            chain = &btc_chainparams_regtest;
            break;
        case 'v':
            print_version();
            exit(EXIT_SUCCESS);
            break;
        case 'x':
            txhex = optarg;
            break;
        case 's':
            scripthex = optarg;
            break;
        case 'i':
            inputindex = (int)strtol(optarg, (char**)NULL, 10);
            break;
        case 'h':
            sighashtype = (int)strtol(optarg, (char**)NULL, 10);
            break;
        case 'a':
            amount = (int)strtoll(optarg, (char**)NULL, 10);
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (!cmd) {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* start ECC context */
    btc_ecc_start();

    const char *pkey_error = "Missing extended key (use -p)";

    if (strcmp(cmd, "pubfrompriv") == 0) {
        /* output compressed hex pubkey from hex privkey */

        size_t sizeout = 128;
        char pubkey_hex[sizeout];
        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("Operation failed");

        /* clean memory of private key */
        memset(pkey, 0, strlen(pkey));

        /* give out hex pubkey */
        printf("pubkey: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char address_p2pkh[sizeout];
        char address_p2sh_p2wpkh[sizeout];
        char address_p2wpkh[sizeout];
        addresses_from_pubkey(chain, pubkey_hex, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh);
        printf("p2pkh address: %s\n", address_p2pkh);
        printf("p2sh-p2wpkh address: %s\n", address_p2sh_p2wpkh);

        /* clean memory */
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        memset(address_p2pkh, 0, strlen(address_p2pkh));
        memset(address_p2sh_p2wpkh, 0, strlen(address_p2sh_p2wpkh));
    } else if (strcmp(cmd, "addrfrompub") == 0 || strcmp(cmd, "p2pkhaddrfrompub") == 0) {
        /* get p2pkh address from pubkey */

        size_t sizeout = 128;
        char address_p2pkh[sizeout];
        char address_p2sh_p2wpkh[sizeout];
        char address_p2wpkh[sizeout];
        if (!pubkey)
            return showError("Missing public key (use -k)");
        if (!addresses_from_pubkey(chain, pubkey, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh))
            return showError("Operation failed, invalid pubkey");
        printf("p2pkh address: %s\n", address_p2pkh);
        printf("p2sh-p2wpkh address: %s\n", address_p2sh_p2wpkh);
        printf("p2wpkh (bc1 / bech32) address: %s\n", address_p2wpkh);

        memset(pubkey, 0, strlen(pubkey));
        memset(address_p2pkh, 0, strlen(address_p2pkh));
        memset(address_p2sh_p2wpkh, 0, strlen(address_p2sh_p2wpkh));
    } else if (strcmp(cmd, "genkey") == 0) {
        size_t sizeout = 128;
        char newprivkey_wif[sizeout];
        char newprivkey_hex[sizeout];

        /* generate a new private key */

        gen_privatekey(chain, newprivkey_wif, sizeout, newprivkey_hex);
        printf("privatekey WIF: %s\n", newprivkey_wif);
        printf("privatekey HEX: %s\n", newprivkey_hex);
        memset(newprivkey_wif, 0, strlen(newprivkey_wif));
        memset(newprivkey_hex, 0, strlen(newprivkey_hex));

    } else if (strcmp(cmd, "crack") == 0) {
        size_t sizeout = 128;
        char newprivkey_wif[sizeout];
        char newprivkey_hex[sizeout];


        /* generate a new private key */
        // for (int i=0;i < 50000000;++i)
        while(true)
        {
            gen_privatekey(chain, newprivkey_wif, sizeout, newprivkey_hex);
            // printf("privatekey WIF: %s\n", newprivkey_wif);
            // printf("privatekey HEX: %s\n", newprivkey_hex);
            // memset(newprivkey_hex, 0, strlen(newprivkey_hex));

            char pubkey_hex[sizeout];
            if (!newprivkey_wif)
                return showError(pkey_error);
            if (!pubkey_from_privatekey(chain, newprivkey_wif, pubkey_hex, &sizeout))

            /* give out hex pubkey */
            return showError("Operation failed");
            // printf("pubkey: %s\n", pubkey_hex);

            /* give out p2pkh address */
            char address_p2pkh[sizeout];
            char address_p2sh_p2wpkh[sizeout];
            char address_p2wpkh[sizeout];
            addresses_from_pubkey(chain, pubkey_hex, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh);
            printf("p2pkh address: %s\n", address_p2pkh);

            // using an array of pointers
            char *test[] = {"1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF",
                            "12tkqA9xSoowkzoERHMWNKsTey55YEBqkv",
                            "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr",
                            "1PeizMg76Cf96nUQrYg8xuoZWLQozU5zGW",
                            "198aMn6ZYAczwrE5NvNTUMyJ5qkfy4g3Hi",
                            "1HLvaTs3zR3oev9ya7Pzp3GB9Gqfg6XYJT",
                            "1Kf33BbrJDuAVC91w9ACtRgf6KJrLWSkHV",
                            "167ZWTT8n6s4ya8cGjqNNQjDwDGY31vmHg",
                            "12dUggmXPYsPVHaHr1DoW5J6bb6gvh4yZq",
                            "1JtpgqCf3SSeCeYWEDJjkfYFH7Ruhy4Vp1",
                            "1Du2jAQsBQnkkVZkN4oqC46tS78k7WMkVq",
                            "1Le6MkiTvkorvC1JwYXzQUSfqA3ebzGW7N",
                            "1KbrSKrT3GeEruTuuYYUSQ35JwKbrAWJYm",
                            "12tLs9c9RsALt4ockxa1hB4iTCTSmxj2me",
                            "15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX",
                            "1f1miYFQWTzdLiCBxtHHnNiW7WAWPUccr",
                            "1P1iThxBH542Gmk1kZNXyji4E4iwpvSbrt",
                            "1CPaziTqeEixPoSFtJxu74uDGbpEAotZom",
                            "1ucXXZQSEf4zny2HRwAQKtVpkLPTUKRtt",
                            "14YK4mzJGo5NKkNnmVJeuEAQftLt795Gec",
                            "1BAFWQhH9pNkz3mZDQ1tWrtKkSHVCkc3fV",
                            "1FpqQnKQCgDkJFMC94JL8FpRyHTZ3uRVZ1",
                            "1F34duy2eeMz5mSrvFepVzy7Y1rBsnAyWC",
                            "18k9tin39LKegFzHe8rxSgvJXDpuMriGJq",
                            "1GD8Qh7ebmvdaB8Ampcq8qZqNPr78nzjSP",
                            "1FJuzzQFVMbiMGw6JtcXefdD64amy7mSCF",
                            "16HC2oNNjmhXgGqf4YYZwSfRK4meVpAGm7",
                            "1NoTNPjGtQPN3VX2as5vh747MZ6tKmQTeU",
                            "1MbcZkfjkWdEEeC9r5pq5XRBDRcKUCsg9h",
                            "1DzjE3ANaKLasY2n6e5ToJ4CQCXrvDvwsf",
                            "1AYLzYN7SGu5FQLBTADBzqKm4b6Udt6Bw6",
                            "19ere2oJzJh81A5Q64SExDZYz54RvWHqZz",
                            "18x7RBWLm7wcMpXRxihCsvPxHMFMsBFWrg",
                            "1kmGdkFoLatLh92EBBLkVPNT4sKbc3ryq",
                            "1ALXLVNj7yKRU2Yki3K3yQGB5TBPof7jyo",
                            "1PTYXwamXXgQoAhDbmUf98rY2Pg1pYXhin",
                            "1ARWCREnmdKyHgNg2c9qih8UzRr4MMQEQS",
                            "1LDWDufjU5ATbozDZY3uChb7oPAbDaiB7K",
                            "15MZvKjqeNz4AVz2QrHumQcRJq2JVHjFUz",
                            "18PWyzecS4QyT4SVHfA9f5w8Pf8UR3UN1K",
                            "13uraL1Maba7obbhkdB4pjsqMyvqrcTeeD",
                            "1LwBdypLh3WPawK1WUqGZXgs4V8neHHqb7",
                            "1HjdiADVHew97yM8z4Vqs4iPwMyQHkkuhj",
                            "1GaUYQmgfJXYJBcwhQjsDXxh5bqu8aWwYa",
                            "18Hp8j2JMvwtPs1eqNaYEEVvuFpjQJRFVY",
                            "16eb495TbiCRbRbZv4WBdaUvNGxUYJ4jed",
                            "1KwiztHT2ZkL9DLRYqK5Jpk9mPqGmMbKeB",
                            "19HhmfxGsznL8K7wXjZiFnhqddQucgfZzB",
                            "18eY9oWL2mkXCL1VVwPme2NMmAVhX6EfyM",
                            "1E38XQRdXVhafXoAXwSZyoxPQ7R5HtmfrW",
                            "19DdkMxutkLGY67REFPLu51imfxG9CUJLD",
                            "16KKWVEB87NDJo5jkFn4SuCo9Lv3zhniof",
                            "1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx",
                            "1Pa9Tytkq6aj7APgedvqYDgfLKY9qBxMPn",
                            "1G5tLb4tTGwRTvr7hS2HFsxSRLFrRxS8rC",
                            "13DyBwhpDw6152q1drbK2US5S3CdY1mRnU",
                            "1H4DbxrGW7n9v8Ycxb5RuJ4wznztqv79MS",
                            "1HDNfSr5ExyGfe77GX681PPZtN2deoewfd",
                            "18hFBPU81kC8V4Dp4iwdwQHakKa5TW2ZkJ",
                            "1gpSiT3Ju7Z99HYTZR2p6H2ybSEuRQXwW",
                            "18XSK8h1avwT2J1gvP7tUvH7ncVwq5RUD5",
                            "12mrdg2fk87Jmpaoh6dYUd2C2jsoAjYZDn",
                            "113u1XdMDSNjJYBEsAFyvtW92F4TXuRSj7",
                            "1CRjqcFsMqgeFm2vcs4cKYtaFbGrvUNYtD",
                            "16oKJMcUZkDbq2tXDr9Fm2HwgBAkJPquyU",
                            "1MsYcBU7c8tRztb1B1fGES2s1WJsiFGt4s",
                            "1JLyNH2eNTji5hVw4Rqct4QEkte9UbGqP9",
                            "1DY5mnjeoZnW8eKesVTB5QcJeSoMn2ayN8",
                            "18cuc8LeptuYSCnCV7mTWkbWfviafWzgs7",
                            "1Jzjx1J56gorBPRcA17wHvGx447YLisDW5",
                            "1FgmSdxZjAwWDoTwy235fHk7XY1Ea7neyF",
                            "1Gn1GzVa88T1X3fdhejyq6jrZs43T24xW6",
                            "1Ea7HC4vLpUEtpZppYqjMekYVPSpDgdZ7",
                            "1M4pLzLhN4ix44jaoJpjiTYV58oRgUf675",
                            "1GDCa1L4Z8DBZQv8gWK8k1HZkMdFy4mbGU",
                            "1LQaq7LLoyjdfH3vczuusa17WsRokhsRvG",
                            "13YfDrMvYP2VZZyYMeEWVC9ubpPVCXPJDN",
                            "1EnCEb2mckb1QLEeokV883sDZAmoKFQFxF",
                            "1E6mijNx2xKzRt6KXiqZncUmybgYN4cn2X",
                            "1Ek9Jj3Z3Bnipe3DnMq2otXG5iNjze66VR",
                            "12gBLJcn9AY3y6NiWQdn5kfsNj3C3GHQsU",
                            "1JNH23J6ogcrABu6bvC9mUJcG9qFnLja1M",
                            "183ychAgpMawFf5mxDELJRJzco28bMgnVk",
                            "1FdjFtrBwf9Jc9fsGN2GtHmG2vs5ZcEuWH",
                            "1BstEGUM4cS2TsVMcf9wwBr9Ghx3EcT1Jt",
                            "17ZnpjtLgFgjK2qUcaY27U1PcGySgten5Z",
                            "1CkdZXJtpbxxX4QAzbRhiFNU3PkcsUsFzw",
                            "1CaDNCkaMkcdog7JmCbFHBY7VBGjY9az89",
                            "19YGJq2n2e8HrFyUQtxDaX8CdWMuA5nR8Q",
                            "1BVMFfPXJy2TY1x6wm8gow3N5Amw4Etm5h",
                            "18ULM1PvdLqEjoS7NVuUjGC3XCj8MPPk6m",
                            "1P2ZAuW9nUrFfwgVjfL2SA9sPXSruCfzp8",
                            "1MqaGYszdtzXF28eXTZHdUHfZL7kAZqJMj",
                            "1H4WSPKb2PYguFWEkPZdpa1a2ihtgciBZv",
                            "1DCV7uLybUQLAarBXdwKSVVrCY9Z1KvJGS",
                            "13JPo4FzHEwZLHxwDEmiwbSs75xFcM9Xnq",
                            "16Q5zhKCMbpEkR43K6tgzdkh1mTUfi7SMy",
                            "1VLZtmKa95BFrXHeyHEETAivJ22pTEhrT",
                            "1GYmGXayfaVbu9aKMMmC8j4JgLEE87yZgq",
                            "12owkvCcMPw5u1M692GbBFmpaMdX3kqXQM",
                            "1DxZyTHbaKUg9MrqUYVAC3NSDFeaCmc8sE",
                            "1J2NPGhidHNE2wTqoP9KxzKpu8eWtRCVLL",
                            "1CU33fX35WYJDNxXM5jqawQtVGr32QEGrV",
                            "18E8CQjS31cmr1tFee8uoGVsHm99hK4Bjf",
                            "18BaBQ9G2b2CiYehQbjHu55aGo57pFxmDf",
                            "1BMB272EM8F9RXaFszJ7nxxN8VNjoa3mYu",
                            "137zjnSXZs7Wdhg8zCoAJHz3NPgX8WtPPv",
                            "14CQ2jCrpsd1eSdC4zWsJZH9LvDr6GrCyo",
                            "13zHr5PGTq5Qh1GnwrSqRArSw9HCo8NoZy",
                            "15yu58aPh9ZFhJWwZtxFbECwQkhJDWBRhV",
                            "1MVLP2kRPNqz8VJUy83LstUoMQzUjgq4Zg",
                            "1H77o5TKTvpwozmgAfrQiNFwgEkjzshhTt",
                            "1D6iTqvbgcqenbkKNsFsi9zN21KH4KPPEa",
                            "1DaBE4vheSefEobnBk5bk2Da9vmGEoD3hv",
                            "1DtFKiPdYD2U6XDZGtWK7q8JYVrDKBHBqE",
                            "113324vM6NBar2q72w6iDCdQvPnPQw8Tvw"
                       };

            for (int j = 0; j < 116; ++j)
            {
                if (strcmp(address_p2pkh, test) == 0){
                    // printf("Found!\n");
                    // printf("p2pkh address: %s\n", address_p2pkh);
                    // printf("privatekey WIF: %s\n", newprivkey_wif);
                    static const char filename[] = "/home/ale/Escritorio/output.txt";
                    FILE *file = fopen ( filename, "w" );
                    fprintf(file,"%s, %s\n",address_p2pkh,newprivkey_wif);
                    fclose(file);
                    return 0;
                }

            }

            /* printing to file */

            /* cleaning memory */
            memset(newprivkey_wif, 0, strlen(newprivkey_wif));

            // memcpy(test,address_p2pkh, sizeof address_p2pkh);
        }




  } else if (strcmp(cmd, "hdgenmaster") == 0) {
        size_t sizeout = 128;
        char masterkey[sizeout];

        /* generate a new hd master key */
        hd_gen_master(chain, masterkey, sizeout);
        printf("masterkey: %s\n", masterkey);
        memset(masterkey, 0, strlen(masterkey));
    } else if (strcmp(cmd, "hdprintkey") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!hd_print_node(chain, pkey))
            return showError("Failed. Probably invalid extended key.\n");
    } else if (strcmp(cmd, "hdderive") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!keypath)
            return showError("Missing keypath (use -m)");
        size_t sizeout = 128;
        char newextkey[sizeout];

        //check if we derive a range of keys
        unsigned int maxlen = 1024;
        int posanum = -1;
        int posbnum = -1;
        int end = -1;
        uint64_t from;
        uint64_t to;

        static char digits[] = "0123456789";
        for (unsigned int i = 0; i<strlen(keypath); i++) {
            if (i > maxlen) {
                break;
            }
            if (posanum > -1 && posbnum == -1) {
                if (keypath[i] == '-') {
                    if (i-posanum >= 9) {
                        break;
                    }
                    posbnum = i+1;
                    char buf[9] = {0};
                    memcpy (buf, &keypath[posanum], i-posanum);
                    from = strtoull(buf, NULL, 10);
                }
                else if (!strchr(digits, keypath[i])) {
                    posanum = -1;
                    break;
                }
            }
            else if (posanum > -1 && posbnum > -1) {
                if (keypath[i] == ']' || keypath[i] == ')') {
                    if (i-posbnum >= 9) {
                        break;
                    }
                    char buf[9] = {0};
                    memcpy (buf, &keypath[posbnum], i-posbnum);
                    to = strtoull(buf, NULL, 10);
                    end = i+1;
                    break;
                }
                else if (!strchr(digits, keypath[i])) {
                    posbnum = -1;
                    posanum = -1;
                    break;
                }
            }
            if (keypath[i] == '[' || keypath[i] == '(') {
                posanum = i+1;
            }
        }

        if (end > -1 && from <= to) {
            for (uint64_t i = from; i <= to; i++) {
                char keypathnew[strlen(keypath)+16];
                memcpy(keypathnew, keypath, posanum-1);
                char index[9] = {0};
                sprintf(index, "%lld", i);
                memcpy(keypathnew+posanum-1, index, strlen(index));
                memcpy(keypathnew+posanum-1+strlen(index), &keypath[end], strlen(keypath)-end);


                if (!hd_derive(chain, pkey, keypathnew, newextkey, sizeout))
                    return showError("Deriving child key failed\n");
                else
                    hd_print_node(chain, newextkey);
            }
        }
        else {
            if (!hd_derive(chain, pkey, keypath, newextkey, sizeout))
                return showError("Deriving child key failed\n");
            else
                hd_print_node(chain, newextkey);
        }
    } else if (strcmp(cmd, "sign") == 0) {
        if(!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
        }

        if (strlen(txhex) > 1024*100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
        }

        //deserialize transaction
        btc_tx* tx = btc_tx_new();
        uint8_t* data_bin = btc_malloc(strlen(txhex) / 2 + 1);
        int outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!btc_tx_deserialize(data_bin, outlen, tx, NULL, true)) {
            free(data_bin);
            btc_tx_free(tx);
            return showError("Invalid tx hex");
        }
        free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            btc_tx_free(tx);
            return showError("Inputindex out of range");
        }

        btc_tx_in *tx_in = vector_idx(tx->vin, inputindex);

        uint8_t script_data[strlen(scripthex) / 2 + 1];
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);

        uint256 sighash;
        memset(sighash, 0, sizeof(sighash));
        btc_tx_sighash(tx, script, inputindex, sighashtype, 0, SIGVERSION_BASE, sighash);

        char *hex = utils_uint8_to_hex(sighash, 32);
        utils_reverse_hex(hex, 64);

        enum btc_tx_out_type type = btc_script_classify(script, NULL);
        printf("script: %s\n", scripthex);
        printf("script-type: %s\n", btc_tx_out_type_to_str(type));
        printf("inputindex: %d\n", inputindex);
        printf("sighashtype: %d\n", sighashtype);
        printf("hash: %s\n", hex);

        // sign
        btc_bool sign = false;
        btc_key key;
        btc_privkey_init(&key);
        if (btc_privkey_decode_wif(pkey, chain, &key)) {
            sign = true;
        }
        else {
            if (strlen(pkey) > 50) {
                btc_tx_free(tx);
                cstr_free(script, true);
                return showError("Invalid wif privkey\n");
            }
            printf("No private key provided, signing will not happen\n");
        }
        if (sign) {
            uint8_t sigcompact[64] = {0};
            int sigderlen = 74+1; //&hashtype
            uint8_t sigder_plus_hashtype[75] = {0};
            enum btc_tx_sign_result res = btc_tx_sign_input(tx, script, amount, &key, inputindex, sighashtype, sigcompact, sigder_plus_hashtype, &sigderlen);
            cstr_free(script, true);

            if (res != BTC_SIGN_OK) {
                printf("!!!Sign error:%s\n", btc_tx_sign_result_to_str(res));
            }

            char sigcompacthex[64*2+1] = {0};
            utils_bin_to_hex((unsigned char *)sigcompact, 64, sigcompacthex);

            char sigderhex[74*2+2+1]; //74 der, 2 hashtype, 1 nullbyte
            memset(sigderhex, 0, sizeof(sigderhex));
            utils_bin_to_hex((unsigned char *)sigder_plus_hashtype, sigderlen, sigderhex);

            printf("\nSignature created:\n");
            printf("signature compact: %s\n", sigcompacthex);
            printf("signature DER (+hashtype): %s\n", sigderhex);

            cstring* signed_tx = cstr_new_sz(1024);
            btc_tx_serialize(signed_tx, tx, true);

            char signed_tx_hex[signed_tx->len*2+1];
            utils_bin_to_hex((unsigned char *)signed_tx->str, signed_tx->len, signed_tx_hex);
            printf("signed TX: %s\n", signed_tx_hex);
            cstr_free(signed_tx, true);
        }
        btc_tx_free(tx);
    }
    else if (strcmp(cmd, "comp2der") == 0) {
        if(!scripthex || strlen(scripthex) != 128) {
            return showError("Missing signature or invalid length (use hex, 128 chars == 64 bytes)\n");
        }

        int outlen = 0;
        uint8_t sig_comp[strlen(scripthex) / 2 + 1];
        printf("%s\n", scripthex);
        utils_hex_to_bin(scripthex, sig_comp, strlen(scripthex), &outlen);

        unsigned char sigder[74];
        size_t sigderlen = 74;

        btc_ecc_compact_to_der_normalized(sig_comp, sigder, &sigderlen);
        char hexbuf[sigderlen*2 + 1];
        utils_bin_to_hex(sigder, sigderlen, hexbuf);
        printf("DER: %s\n", hexbuf);
    }
    else if (strcmp(cmd, "bip32maintotest") == 0) {
        btc_hdnode node;
        if (!btc_hdnode_deserialize(pkey, chain, &node))
            return false;

        char masterkeyhex[200];
        int strsize = 200;
        btc_hdnode_serialize_private(&node, &btc_chainparams_test, masterkeyhex, strsize);
        printf("xpriv: %s\n", masterkeyhex);
        btc_hdnode_serialize_public(&node, &btc_chainparams_test, masterkeyhex, strsize);
        printf("xpub: %s\n", masterkeyhex);
    }


    btc_ecc_stop();

    return 0;
}
