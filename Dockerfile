FROM alpine:3.20

# Create /app with a sample file that contains strings matched by GenericGh0st
RUN mkdir -p /app \
 && printf "AVCKernelManager\nAVCShellManager\nAVCClientSocket\nChoosing with administrator privileges: %s.\n" > /app/gh0st_sample.txt

# Keep the container running for scanning
CMD ["sleep", "infinity"]