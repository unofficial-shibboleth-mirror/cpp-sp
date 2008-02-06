#! /bin/sh

while getopts h:y:b c
     do
         case $c in
           b)         BATCH=1;;
           h)         FQDN=$OPTARG;;
           y)         DAYS=$OPTARG;;
           \?)        echo keygen [-h hostname/cn for cert] [-y years to issue cert]
                      exit 1;;
         esac
     done

if  [ -e sp-key.pem ] || [ -e sp-cert.pem ] ; then
    if [ -z $BATCH ] ; then  
        echo The files sp-key.pem and/or sp-cert.pem already exist!
        exit 2
    fi
    exit 0
fi

if [ -z $FQDN ] ; then
    FQDN=`hostname`
fi

if [ -z $DAYS ] ; then
    DAYS=10
fi

DAYS=$(($DAYS*365))

openssl req -x509 -days $DAYS -newkey rsa:2048 -nodes -keyout sp-key.pem -out sp-cert.pem -subj /CN=$FQDN -extensions usr_cert -set_serial 0
