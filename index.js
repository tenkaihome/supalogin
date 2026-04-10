import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import admin from 'firebase-admin';
import { readFileSync } from 'fs';

dotenv.config();

// Đọc file chứng chỉ admin
let serviceAccount;
try {
    const fileContent = readFileSync('./serviceAccountKey.json', 'utf-8');
    serviceAccount = JSON.parse(fileContent);
} catch (error) {
    console.error("LỖI: Không tìm thấy file serviceAccountKey.json hoặc file không đúng định dạng JSON.");
    process.exit(1);
}

// Khởi tạo Firebase Admin (Bỏ qua mọi rules)
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://unichat-acfc2-default-rtdb.firebaseio.com"
});

const db = admin.database();
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_123';

// Khởi tạo tài khoản Admin mặc định
const initDefaultAdmin = async () => {
    try {
        const username = 'lichdt';
        const password = '389363';
        
        const adminRef = db.ref(`users/${username}`);
        const snapshot = await adminRef.once('value');

        if (!snapshot.exists()) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            
            await adminRef.set({
                username: username,
                password: hashedPassword,
                role: 1 // 1 = admin, 2 = guest, 3 = user
            });
            console.log(`Tài khoản Admin mặc định '${username}' đã được tạo thành công!`);
        } else {
            console.log(`Tài khoản Admin mặc định '${username}' đã tồn tại và sẵn sàng.`);
        }
    } catch (error) {
        console.error("Lỗi khi tạo Admin mặc định:", error);
    }
};

initDefaultAdmin();

// Middleware xác thực Token JWT
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Không có quyền truy cập (Unauthorized)' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
    }
};

// Middleware kiểm tra quyền Admin
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 1) {
        return res.status(403).json({ error: 'Bị từ chối: Cần có quyền Admin' });
    }
    next();
};

// API: Tạo tài khoản (Signup)
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Vui lòng cung cấp username và password' });
    }

    try {
        const userRef = db.ref(`users/${username}`);
        const snapshot = await userRef.once('value');
        
        if (snapshot.exists()) {
            return res.status(409).json({ error: 'Username này đã tồn tại' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await userRef.set({
            username,
            password: hashedPassword,
            role: 3 // Theo yêu cầu, mặc định tài khoản mới có quyền guest (3)
        });

        res.status(201).json({
            message: 'Signup successful! You are currently a Guest (3). Please wait for Admin approval.'
        });
    } catch (error) {
        console.error("Lỗi Signup:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API: Đăng nhập (Login)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Vui lòng cung cấp username và password' });
    }

    try {
        const userRef = db.ref(`users/${username}`);
        const snapshot = await userRef.once('value');

        if (!snapshot.exists()) {
            return res.status(401).json({ error: 'Username hoặc password không đúng' });
        }

        const user = snapshot.val();
        
        let isMatch = false;
        try {
            isMatch = await bcrypt.compare(password, user.password);
        } catch (e) {
            if (password === user.password) {
                isMatch = true;
            }
        }
        
        if (!isMatch && password === user.password) {
            isMatch = true;
        }

        if (!isMatch) {
            return res.status(401).json({ error: 'Username hoặc password không đúng' });
        }

        const token = jwt.sign(
            { username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Đăng nhập thành công',
            token,
            user: {
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Lỗi Login:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (Admin): Cấp quyền cho user
app.post('/api/admin/grant-role', authenticate, requireAdmin, async (req, res) => {
    const { targetUsername, newRole } = req.body;
    
    if (!targetUsername || newRole === undefined) {
        return res.status(400).json({ error: 'Cần cung cấp targetUsername và newRole' });
    }

    if (![1, 2, 3].includes(Number(newRole))) {
        return res.status(400).json({ error: 'Quyền không hợp lệ. Phải là 1 (admin), 2 (guest), hoặc 3 (user).' });
    }

    try {
        const userRef = db.ref(`users/${targetUsername}`);
        const snapshot = await userRef.once('value');

        if (!snapshot.exists()) {
            return res.status(404).json({ error: `Tài khoản ${targetUsername} không tồn tại` });
        }

        // Cập nhật quyền mới
        await userRef.update({ role: Number(newRole) });
        res.json({ message: `Cập nhật quyền thành công! Tài khoản ${targetUsername} đã được cấp quyền ${newRole}.` });
    } catch (error) {
         console.error("Lỗi Grant role:", error);
         res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (Admin): Danh sách các User
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
    try {
        const usersRef = db.ref('users');
        const snapshot = await usersRef.once('value');
        
        if (!snapshot.exists()) {
            return res.json([]);
        }

        const usersData = snapshot.val();
        // Lọc bỏ password
        const usersList = Object.keys(usersData).map(key => ({
            username: usersData[key].username,
            role: usersData[key].role
        }));

        res.json(usersList);
    } catch (error) {
        console.error("Lỗi get users:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (Test / Template cho các chức năng khác cho user sử dụng)
app.get('/api/protected-feature', authenticate, (req, res) => {
    if (req.user.role === 2) {
        return res.status(403).json({ error: 'Từ chối: Guest không không có quyền sử dụng tính năng này.' });
    }
    
    res.json({ message: 'Tính năng truy cập thành công', userRole: req.user.role });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server đang chạy trên cổng ${PORT}`);
});
