# How to create cpp files out of *.proto file
1. protoc -I . --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` rule_messages.proto
2. protoc -I . --cpp_out=. rule_messages.proto

# Installing the necessary libraries for GRPC
sudo apt-get install protobuf-compiler libprotobuf-dev libgrpc++-dev protobuf-compiler-grpc
