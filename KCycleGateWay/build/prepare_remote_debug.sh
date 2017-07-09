# Kill gdbserver if it's running
ssh pi@192.168.11.12 killall gdbserver &> /dev/null
# Compile myprogram and launch gdbserver, listening on port 9091
ssh \
  -L9091:localhost:9091 \
  pi@192.168.11.12 \
  "sh -l -c 'cd ~/project/KCycleGateWay/KCycleGateWay/Debug && make && gdbserver :9091 ./KCycleGateWay'"