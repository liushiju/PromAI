lsof -ti:8091 | xargs kill -9
sleep 1
> nohup.out
nohup  go run main.go &