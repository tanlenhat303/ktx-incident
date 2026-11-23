# Hệ thống quản lý sự cố KTX ĐHQG-HCM

Node.js + Express + SQLite (better-sqlite3). Giao diện thuần HTML/JS trong `public/`.

## Chạy
```bash
npm install
npm start          # http://localhost:3000
```
Tài khoản ban quản lý mặc định: `admin` / `admin123`
(đổi bằng `ADMIN_PASSWORD=... SESSION_SECRET=... npm start`).
Sinh viên tự đăng ký bằng MSSV, họ tên, email, **trường học** và tòa/phòng.

## Cấu trúc CSDL
`users` (sinh viên + admin) · `rooms` · `requests` · `request_media` (ảnh/video đính kèm) · `request_history`

Ảnh/video lưu trong thư mục `uploads/` (tự tạo). Cho phép JPG, PNG, GIF, WebP, MP4, WebM, MOV; tối đa 5 tệp/yêu cầu, ảnh ≤ 8MB, video ≤ 50MB. Tệp chỉ xem được khi đăng nhập (chủ yêu cầu hoặc admin).

## API chính
| Method | Đường dẫn | Quyền |
|---|---|---|
| POST | /api/register, /api/login, /api/logout | - |
| POST | /api/forgot-password `{email}` · /api/reset-password `{token, password}` | - |
| GET | /api/me, /api/meta | - |
| POST | /api/requests (multipart: category, priority, description, media[]) | sinh viên |
| GET | /api/media/:id | chủ yêu cầu / admin |
| GET | /api/requests?status=&category= | đăng nhập (SV chỉ thấy của mình) |
| PATCH | /api/requests/:id  `{status, assignee}` | admin |
| GET | /api/requests/:id/history | chủ yêu cầu / admin |
| GET | /api/stats | admin |
