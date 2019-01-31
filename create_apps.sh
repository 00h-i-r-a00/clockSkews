#!/bin/bash

num_apps=$1
path_var='/home/hira/research/clock_skew_scripts/grace_periods/apps'
start=expr
password="gandalf287"


##delete all previous crt's and keys
##TODO: create separate folders for not before and not after
rm -rf "$path_var/$domain_name_dir/time*"

for((i=1;i<=num_apps;i++))
do
    domain_name_dir="time"$i"_securepki_org"
    domain_name="time"$i".securepki.org"
    path_to_dir="$path_var/$domain_name_dir/"
    cp -a "$path_var/subdomain1" "$path_var/$domain_name_dir"
    sed -i -e "s/time.securepki.org/time$i.securepki.org/g" "$path_var/$domain_name_dir/app.py"
    sed -i -e 's/127.0.0.1/127.0.0.'$i'/g' "$path_var/$domain_name_dir/app.py"
    cp -a "/home/hira/research/clock_skew_scripts/grace_periods/$domain_name.key" $path_to_dir
    cp -a "/home/hira/research/clock_skew_scripts/grace_periods/$domain_name.crt" $path_to_dir
    echo $password | sudo echo "127.0.0.$i   $domain_name" >> /etc/hosts 
    echo $password | sudo echo "127.0.0.$i   www.$domain_name" >> /etc/hosts   
    echo $password | sudo python3 "$path_var/$domain_name_dir/app.py" &
done
##deploy apps
