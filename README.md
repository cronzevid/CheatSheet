# Zip-bomb
head -c 1G </dev/urandom > 1; zip -9 backup.zip 1; while true; do for i in {1..5}; do cp backup.zip "backup.zip$i"; done; rm backup.zip; zip -9 backup.zip backup.zip*; for i in {1..5}; do rm "backup.zip$i"; done; ll backup.zip; sleep 1; done

# Draw like a rockstar
ipmitool sel elist | grep 'General Chassis intrusion' | awk '{print $3}' | sort | uniq -c | awk '{print $2" "$1}' | sort | awk '{$2=sprintf("%-*s", $2, ""); gsub(" ", "=", $2); printf("%-10s 8%s3\n", $1, $2)}'

# Find deleted files
lsof -nP +L1
lsof -nP | grep '(deleted)'
find /proc/*/fd -ls | grep  '(deleted)'

# Hack diff
diff <(cat /etc/passwd) <(cut -f2 /etc/passwd)

# Exim oneliners
exim -bp | egrep '<.*>' | sort -k 4
exim -bp | egrep '<.*>' | sort -k 4 | egrep -v "[0-9]{1,2}m" | awk '{print $3}' | xargs exim -Mrm
for i in `exim -bp | egrep '<.*>' | sort -k 4 | awk '{print $4}' | sort | uniq -c | sort -n | awk '{print $2}' | tail`; do exim -bp | grep $i | egrep -v "[0-9]{1,2}m" | awk '{print $3}' | xargs exim -Mrm ; done
exim -bp | egrep '<.*>' | sort -k 4 | awk '{print $4}' | sort | uniq -c | sort -n | awk '{sum += $1} END {print sum}'
exim -bp | grep '<>' | awk '{print $3}' | xargs exim -Mrm

# Docker healtchecks
for i in `docker ps | grep unhealthy | awk '{print $NF}'`; do echo $i; docker exec $i curl -sIL http://localhost:80/server-status/ | grep 200; echo; done
for i in `docker ps | grep unhealthy | awk '{print $NF}'`; do docker exec $i curl -sIL http://localhost:80/server-status/ | grep 200; done | wc -l

# Semi-automaed f2b actions
tailf /var/log/nginx/access.log | grep domain.com | awk '{print $6}' > ips.txt
for i in `cat ips.txt | sort | uniq`; do fail2ban-client set nginx-suspicious-requests banip $i; done

# Automaed ipset/f2b actions
tailf /var/log/nginx/access.log | grep 'domain.com' | awk '{system ("ipset -q test f2b-http "$6"; if [ $? -eq 1 ]; then fail2ban-client set nginx-suspicious-requests banip "$6" ; fi;")}'

# Semi-automaed ipset actions
for i in `cat new_bad_ips | sort | uniq`; do ipset -q test f2b-http $i; if [ $? -eq 1 ]; then fail2ban-client set nginx-suspicious-requests banip $i; fi; done

# Ban via ipset
ipset add f2b-http  45.14.49.161 timeout 4294967

# Find D/Uninterruptable sleep
for x in `seq 1 1 10`; do ps -eo state,pid,cmd | grep "^D"; echo "----"; sleep 5; done
pidstat -dl 20 (io load)

# Find hardlinked files
find / -type f -links +1 -printf '%i %n %p\n' | sort -k 3

# Find inode usage per dir on one fs
du --inodes --max-depth 1 /

# Renice
renice 10 -u user

# MySQL stats
myroot -e 'SELECT * FROM INFORMATION_SCHEMA.USER_STATISTICS;'
myroot -e 'SELECT user,total_connections,concurrent_connections,connected_time,cpu_time,bytes_received,bytes_sent,rows_fetched FROM information_schema.user_statistics ORDER BY cpu_time;'

# MySQL check crashed db
for i in `tailf /var/log/mysql-customer.log | grep crashed | awk '{print $6} | cut -d "/" -f 1'`; do mysqlcheck --repair --databases $i; done
mysqlcheck --defaults-file=/opt/configs/.my.cnf --all-databases -r

# Longest current queries
myroot -e "show full processlist" | grep -v admin_conf | sort -nk 6

# grep with answer code count
zgrep --no-filename 185.167.216.129 /var/log/nginx/access.log* | awk '{print substr($1,5,11), $5}' | sort -k 1 | uniq -f 1 -c

# sed between dates
zcat /var/log/nginx/access.log.* | sort | sed -n '/01\/Feb\/2019:23:50/,/02\/Feb\/2019:00:10/p'

# cgroup write throttle
echo "253:2 2194304" >! /sys/fs/cgroup/blkio/users/a0268545-shared3/blkio.throttle.write_bps_device

# stdout streaming fix
stdbuf -i0 -o0 -e0 tail -f /var/log/nginx/access.log | stdbuf -i0 -o0 -e0 grep projectene | awk '{print $6}' > ips.list

# Process start time
```
## ps -o etime= -p 25079 # [[dd-]hh:]mm:ss
# 9-09:46:29

## ps -o etimes= -p 25079 # seconds
# 812810

## stat -c%X /proc/25079
#1532722322
## date +%s --date="now - $( stat -c%X /proc/25079 ) seconds"
#143
## ps -o stime,time 25079
#STIME     TIME
#Jul18 00:10:26
```

# jq conditioning
cat boxes.json | jq '.domains[] | select(.domain == "domains.com").boxes[] | select(.username == "username")'

# Exact process ram
for i in `ps aux | grep username | grep httpd | awk '{print $2}'`; do grep VmRSS /proc/$i/status; done | awk '{sum += $2} END {print sum}'

# Long watch
watch "grep -c 'core id' /proc/cpuinfo; uptime; echo; vmstat; echo ; free -h; echo; echo -n "Exited containers: "; docker ps -a | grep Exited | wc -l; echo; echo -n "Unhealthy containers: "; docker ps | grep unhealt | wc -l "

# Update precautios
yum --disablerepo="*" --enablerepo="privaterepo" list available | awk '{print $1}' | tr '\n' ' '

# Update hosting
systemctl stop chef-client
yum --disablerepo="*" --enablerepo="centos-base,centos-updates" --exclude `Update precautios` update
chef-client --once
systemctl reboot

# md speed
echo 2000 >! /sys/block/md126/md/sync_speed_min

# set dirty buffer
sysctl -w dirty_bytes=134217728 (128 Мб)
sysctl -w vm.dirty_background_bytes=67108864 (64 Мб)

# throttle io hack
while true; do sleep 10; kill -CONT 23795 23795; sleep 1; kill -STOP 23795 23795;done

# OVN aliases
ovn-nbctl --db tcp:10.0.0.113:6641 list Logical_Switch_Port
ovn-sbctl --db tcp:10.0.0.113:6642 show | grep hostname | sort | uniq -c | sort -n
ovn-sbctl --db tcp:10.0.0.113:6642 find Chassis
ovn-sbctl --db tcp:10.0.0.113:6642 find Chassis hostname=hostname.local
ovsdb-client list-dbs tcp:10.0.0.113:6642
ovsdb-client get-schema tcp:10.0.0.113:6642 OVN_Southbound | jq .
ovsdb-client get-schema tcp:10.0.0.113:6642 OVN_Southbound | jq .tables.Chassis

# IO scheduler
cat /sys/block/*/queue/scheduler

# iptables
iptables -I INPUT -j ACCEPT
iptables -L --line-numbers
iptables -D INPUT 9

