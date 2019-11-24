# Giới thiệu
- Khi tôi làm việc trên công ty, có một số điều khó chịu, đó là mạng của công ty đã không cho tôi truy cập vào các trang web như: telegram, discord, slack,.. Bắt buộc tôi phải sử dụng vpn (với cấu hình tcp ở port 443). Điều này thật khó chịu, và tôi là sinh viên, làm gì có tiền thuê vps chứ.
Hơn nữa, tốc độ truy cập giảm đáng kể khi ta sử dụng vpn hay socks.
- Gần đây, các nhà mạng viễn thông Việt Nam đã đồng loạt chặn truy cập với các website 18+, khiến cư dân hoang mang, nhiều bạn lên voz lập topic, gây loãng.

Do vậy, với nhu cầu, tình hình hiện tại, tôi đã nảy ra ý tưởng này. Và đây là sản phẩm
- Trước tiên, chúng ta cần tìm hiểu xem ISP, Công ty,.. họ đã chặn truy cập như thế nào:
 * Họ không chặn qua IP của trang web mà ta truy cập tới (chặn IP mà IP nó của cloudflare thì chết =)) )
 * Họ không chặn dns, chắc họ biết là chặn dns thì còn có dns-over-https =))
 * Với HTTP, điều này không khó, mọi thứ ở dạng rõ, họ chặn qua `Host` header
 * Với HTTPS, họ không thể lấy Header của ta được, họ chặn qua SNI (ở bước Hello server của ta, làm gián đoạn quá trình bắt tay này), vậy nếu ta thay đổi chuỗi SNI này, họ sẽ không chặn ta nữa. Trước đó, tôi có đọc được một bài viết của một cậu học sinh cấp 3, cậu ta vượt qua filter SNI của hệ thống mạng wifi trên máy bay (hiện tại bài viết đã bị xóa bỏ, cả ở trên wayback machine) khiến cho tôi càng muốn một cách dễ dàng hơn để thực hiện điều này.

# Sử dụng
## Yêu cầu đơn giản nhất
- Bạn đã tải về phần mềm của tôi ở mục [Releases](https://github.com/vinhjaxt/go-fasthttp-sniproxy/releases)
- Bạn có Extension để thay đổi Proxy trên Chrome hoặc Firefox (khuyên dùng foxyproxy)
- Có một số kiến thức liên quan (hoặc nhờ người bạn xã hội nào đó =))) )
## Các bước thực hiện
- Xác định tên miền trang web mà bạn muốn vượt: ví dụ telegram.org, discordapp.com
- Tải và Cài đặt chứng chỉ này trên máy hay trình duyệt của bạn: [ca.pem](https://raw.githubusercontent.com/vinhjaxt/go-fasthttp-sniproxy/master/ca.pem)
- Giải nén file bạn đã download về, liệt kê các tên miền đó rồi cho vào file `domains.txt` (hoặc, nếu bạn biết về regular expression, bạn có thể thay đổi file `domains-regex.txt` để thực hiện điều tương tự)
- Chạy phần mềm của tôi, bạn có thể thêm `-h` để xem các options
- Thay đổi proxy của trình duyệt hay hệ thống: Cấu hình foxyproxy như ảnh dưới đây
![image](https://user-images.githubusercontent.com/8877695/69479251-c040a280-0e2d-11ea-9564-f8cd757c1879.png)
- Sử dụng cấu hình này
- Truy cập trang web mà bạn muốn (sử dụng https:// )
## Hướng dẫn chi tiết
- [Các bước sử dụng trên windows](https://github.com/vinhjaxt/go-fasthttp-sniproxy/issues/1)

# Thông tin thêm
- Vì thay đổi SNI nên cert của trang web trả về đôi khi sẽ không đúng với tên miền ta cần, nên bạn có thể thay đổi file `domains-certs.json` để định nghĩa các alias domain cho việc verify
- Sử dụng `-k` để bỏ qua việc verify này (chú ý MITM)
- Với TLS1.3, firefox đã có thể encrypt SNI, bạn không cần dùng tool này, dùng firefox thôi là đc rồi (nhưng mà đâu phải trang nào cũng hỗ trợ TLS1.3 đâu :(( )

# Credits and Thanks
- Thank to @eternal-flame-AD https://github.com/eternal-flame-AD/go-pixiv
- Thank to @elazarl https://github.com/elazarl/goproxy
