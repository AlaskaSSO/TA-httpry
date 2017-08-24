#!/bin/bash
#NOTICE download file from urlblacklist.com;  this is a COMMERCIAL service!  You can use ONE file one time for testing purposes
## cd to blacklist directory
CATEGORIESFILE=`mktemp`
> httpry_category.csv
echo "dest,category" > httpry_category.csv
find .|grep domains|cut -f2 -d'/' > $CATEGORIESFILE
while read -r category || [[ -n "$category" ]]; do
while read -r dest || [[ -n "$dest" ]]; do
echo "$dest,$category" >> httpry_category.csv
done < "$category/domains"
done < "$CATEGORIESFILE"
#Now we're at the end... add at the end some common wildcards for well-known domains
#this should pick up a large amount of leftover sites
echo "*.gov,government" >> httpry_category.csv
echo "*.adult,porn" >> httpry_category.csv
echo "*.sexy,porn" >> httpry_category.csv
echo "*.singles,adult" >> httpry_category.csv
echo "*.soccer,sports" >> httpry_category.csv
echo "*.xxx,porn" >> httpry_category.csv
echo "*.akamaihd.net,Content Server" >> httpry_category.csv
echo "*.state.ak.us,Content Server" >> httpry_category.csv
rm $CATEGORIESFILE

