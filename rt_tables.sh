num=$1
for((i=0;i<$num;i++)) 
do 
    echo "$((252-$i)) ppp$i" >> /etc/iproute2/rt_tables
done
