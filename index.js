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
                role: user.role,
                avatar: user.avatar || ""
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
        
        const targetUser = snapshot.val();
        
        // Logical check: Super Admin rules
        if (targetUsername === 'lichdt' && req.user.username !== 'lichdt') {
            return res.status(403).json({ error: 'Không thể thay đổi quyền của Super Admin' });
        }
        if (targetUser.role === 1 && req.user.username !== 'lichdt' && targetUsername !== req.user.username) {
            return res.status(403).json({ error: 'Chỉ Super Admin (lichdt) mới có thể sửa quyền Admin khác' });
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
        const now = Date.now();
        const usersList = Object.keys(usersData).map(key => ({
            username: usersData[key].username,
            role: usersData[key].role,
            avatar: usersData[key].avatar || "",
            is_online: (now - (usersData[key].last_active || 0)) < 60000
        }));

        res.json(usersList);
    } catch (error) {
        console.error("Lỗi get users:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (Admin): Xoá tài khoản người dùng
app.delete('/api/admin/users/:username', authenticate, requireAdmin, async (req, res) => {
    const { username } = req.params;
    if (!username) {
        return res.status(400).json({ error: 'Cần cung cấp username' });
    }
    // Không cho phép xoá tài khoản tự xoá chính mình (an toàn)
    if (username === req.user.username) {
        return res.status(403).json({ error: 'Không thể tự xoá chính mình' });
    }
    if (username === 'lichdt') {
        return res.status(403).json({ error: 'Không thể xoá Super Admin' });
    }
    try {
        const userRef = db.ref(`users/${username}`);
        const snapshot = await userRef.once('value');
        if (!snapshot.exists()) {
            return res.status(404).json({ error: `Tài khoản ${username} không tồn tại` });
        }
        
        const targetUser = snapshot.val();
        if (targetUser.role === 1 && req.user.username !== 'lichdt') {
            return res.status(403).json({ error: 'Chỉ Super Admin (lichdt) mới có quyền xoá Admin khác' });
        }

        await userRef.remove();
        res.json({ message: `Xoá tài khoản ${username} thành công!` });
    } catch (error) {
        console.error("Lỗi xoá user:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Nạp danh sách thẻ (Bulk add)
app.post('/api/user/cards', authenticate, async (req, res) => {
    try {
        const { cards } = req.body;
        if (!Array.isArray(cards)) return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
        
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        const snapshot = await cardsRef.once('value');
        let currentCards = snapshot.val() || [];
        
        currentCards = [...currentCards, ...cards];
        await cardsRef.set(currentCards);
        
        res.json({ message: 'Đã nạp thẻ vào hàng đợi', count: currentCards.length });
    } catch (error) {
        console.error("Lỗi nạp thẻ:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Lấy thẻ tiếp theo
app.get('/api/user/cards/next', authenticate, async (req, res) => {
    try {
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        const snapshot = await cardsRef.once('value');
        let cards = snapshot.val() || [];
        
        if (cards.length > 0) {
            res.json({ card: cards[0], remaining: cards.length });
        } else {
            res.json({ card: null, remaining: 0 });
        }
    } catch (error) {
        console.error("Lỗi lấy thẻ:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Xoá thẻ trên cùng (đã xử lý xong)
app.delete('/api/user/cards/top', authenticate, async (req, res) => {
    try {
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        const snapshot = await cardsRef.once('value');
        let cards = snapshot.val() || [];
        
        if (cards.length > 0) {
            cards.shift();
            await cardsRef.set(cards);
        }
        res.json({ success: true, remaining: cards.length });
    } catch (error) {
        console.error("Lỗi xoá thẻ top:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Lấy toàn bộ danh sách thẻ
app.get('/api/user/cards', authenticate, async (req, res) => {
    try {
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        const snapshot = await cardsRef.once('value');
        let cards = snapshot.val() || [];
        res.json({ cards });
    } catch (error) {
        console.error("Lỗi lấy toàn bộ thẻ:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Xoá toàn bộ thẻ trong hàng đợi
app.delete('/api/user/cards', authenticate, async (req, res) => {
    try {
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        await cardsRef.remove();
        res.json({ success: true, message: 'Đã xoá toàn bộ thẻ' });
    } catch (error) {
        console.error("Lỗi xoá queue:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Xoá thẻ tại vị trí index
app.delete('/api/user/cards/index/:index', authenticate, async (req, res) => {
    try {
        const { index } = req.params;
        const idx = Number(index);
        const cardsRef = db.ref(`users/${req.user.username}/cardsQueue`);
        const snapshot = await cardsRef.once('value');
        let cards = snapshot.val() || [];
        if (idx >= 0 && idx < cards.length) {
            cards.splice(idx, 1);
            await cardsRef.set(cards);
            res.json({ success: true, remaining: cards.length });
        } else {
            res.status(400).json({ error: 'Vị trí không tồn tại' });
        }
    } catch (error) {
        console.error("Lỗi xoá thẻ tại index:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Cập nhật trạng thái hoạt động (Ping)
app.put('/api/user/ping', authenticate, async (req, res) => {
    try {
        const userRef = db.ref(`users/${req.user.username}`);
        await userRef.update({ last_active: Date.now() });
        res.json({ success: true });
    } catch (error) {
        console.error("Lỗi ping:", error);
        res.status(500).json({ error: 'Lỗi server nội bộ' });
    }
});

// API (User): Cập nhật profile (Avatar, Username, Password)
app.put('/api/user/profile', authenticate, async (req, res) => {
    const { newAvatar, newPassword, newUsername } = req.body;
    const oldUsername = req.user.username;
    
    try {
        const oldUserRef = db.ref(`users/${oldUsername}`);
        const snapshot = await oldUserRef.once('value');
        if (!snapshot.exists()) return res.status(404).json({ error: 'Tài khoản không tồn tại' });
        
        let userData = snapshot.val();
        
        if (newPassword) {
            const { oldPassword } = req.body;
            if (!oldPassword) {
                return res.status(400).json({ error: 'Cần cung cấp mật khẩu cũ để đổi mật khẩu' });
            }
            
            let isMatch = false;
            try {
                isMatch = await bcrypt.compare(oldPassword, userData.password);
            } catch (e) {
                if (oldPassword === userData.password) isMatch = true;
            }
            if (!isMatch && oldPassword === userData.password) {
                isMatch = true;
            }

            if (!isMatch) {
                return res.status(401).json({ error: 'Mật khẩu cũ không đúng' });
            }

            const salt = await bcrypt.genSalt(10);
            userData.password = await bcrypt.hash(newPassword, salt);
        }
        
        if (newAvatar !== undefined) {
            userData.avatar = newAvatar;
        }

        let tokenHasChanged = false;
        let targetUsername = oldUsername;

        if (newUsername && newUsername !== oldUsername) {
            const newUserRef = db.ref(`users/${newUsername}`);
            const newSnapshot = await newUserRef.once('value');
            if (newSnapshot.exists()) {
                return res.status(400).json({ error: 'Username này đã tồn tại' });
            }
            
            userData.username = newUsername;
            
            const updates = {};
            updates[`users/${newUsername}`] = userData;
            updates[`users/${oldUsername}`] = null;
            await db.ref().update(updates);
            
            targetUsername = newUsername;
            tokenHasChanged = true;
        } else {
            await oldUserRef.set(userData);
        }

        let newToken;
        if (tokenHasChanged) {
            newToken = jwt.sign(
                { username: targetUsername, role: userData.role },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
        }

        res.json({
            message: 'Cập nhật thành công',
            user: {
                username: userData.username,
                role: userData.role,
                avatar: userData.avatar || ""
            },
            token: newToken
        });

    } catch (error) {
        console.error("Lỗi cập nhật profile:", error);
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
