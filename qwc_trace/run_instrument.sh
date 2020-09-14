#/bin/bash


for((i=0;i<999;i++))
do
	sleep 1
	num=`jps | grep Worker | awk '{print $1}'`
	if [ ${num} ];then
		${BYTEMAN_HOME}/bin/bminstall.sh ${num}
		
		#sleep 1
		${BYTEMAN_HOME}/bin/bmsubmit.sh -l slave_trace.btm
		echo "Instru On Slave Succeed!"
                break
	fi
	#echo "No Executor Found"
	
done
 

