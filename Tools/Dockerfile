FROM alpine:latest
WORKDIR /app
COPY ./Tools/vt .
RUN chmod 755 /app/vt
# COPY vt .
# RUN go build -o rest Rest.go
EXPOSE 8000

CMD ["/app/vt"]
 