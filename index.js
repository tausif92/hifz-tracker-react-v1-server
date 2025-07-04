import {
	parasSurahData,
	defaultProgress,
	defaultPara,
} from "./default_data.js";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";

const app = express();
const port = 4000;
const JWT_SECRET = "your_secret_key_here";

const db = new Database("progress.db");

// ------------------ TABLES ------------------

db.prepare(
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		full_name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		currentPara TEXT,
		role TEXT DEFAULT 'user',
		register_date TEXT NOT NULL
	)`
).run();

db.prepare(
	`CREATE TABLE IF NOT EXISTS progress (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		para TEXT NOT NULL,
		completed_pages INTEGER NOT NULL DEFAULT 0,
		total_pages INTEGER NOT NULL,
		start_date TEXT,
		end_date TEXT,
		UNIQUE(user_id, para),
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`
).run();

db.prepare(
	`CREATE TABLE IF NOT EXISTS activity_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		para TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		pages_memorized INTEGER,
		updated_field TEXT NOT NULL,
		previous_value TEXT,
		new_value TEXT,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`
).run();

db.prepare(
	`CREATE TABLE IF NOT EXISTS para_surah (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		para TEXT NOT NULL,
		surah TEXT NOT NULL,
		page INTEGER NOT NULL,
		mistakes INTEGER DEFAULT 0,
		UNIQUE(user_id, para, page),
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`
).run();

app.use(cors());
app.use(express.json());

// ------------------ AUTH ------------------

function authenticate(req, res, next) {
	const authHeader = req.headers.authorization;
	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return res.status(401).json({ message: "Unauthorized" });
	}
	try {
		const token = authHeader.split(" ")[1];
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = { id: decoded.user_id }; // ✅ ensure consistent access
		next();
	} catch (err) {
		res.status(401).json({ message: "Invalid token" });
	}
}

app.post("/register", async (req, res) => {
	const { fullName, email, password } = req.body;
	try {
		const existingUser = db
			.prepare("SELECT * FROM users WHERE email = ?")
			.get(email);

		if (existingUser) {
			return res.status(409).json({
				message: "User already exists. Please log in instead.",
			});
		}
		const hashed = await bcrypt.hash(password, 10);
		const now = new Date().toLocaleString("en-IN", {
			timeZone: "Asia/Kolkata",
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			hour12: true,
		});
		const result = db
			.prepare(
				"INSERT INTO users (full_name, email, password, currentPara, register_date) VALUES (?, ?, ?, ?, ?)"
			)
			.run(fullName, email, hashed, defaultPara, now);

		const userId = result.lastInsertRowid;

		const insertProgress = db.prepare(`
			INSERT INTO progress (user_id, para, completed_pages, total_pages)
			VALUES (?, ?, ?, ?)
		`);
		const insertManyProgress = db.transaction(() => {
			defaultProgress.forEach((p) => {
				insertProgress.run(userId, p.para, p.completed, p.total);
			});
		});
		insertManyProgress();

		const insertSurah = db.prepare(`
			INSERT INTO para_surah (user_id, para, surah, page, mistakes)
			VALUES (?, ?, ?, ?, ?)
		`);
		const insertManySurahs = db.transaction(() => {
			parasSurahData.forEach((s) => {
				insertSurah.run(userId, s.para, s.surah, s.page, s.mistakes);
			});
		});
		insertManySurahs();

		res.json({
			message:
				"User registered and progress & revision data is initialized",
		});
	} catch (err) {
		res.status(500).json({
			message: "Registration failed",
			error: err.message,
		});
	}
});

app.post("/login", async (req, res) => {
	const { email, password } = req.body;
	const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
	if (!user) return res.status(401).json({ message: "Invalid credentials" });
	const match = await bcrypt.compare(password, user.password);
	if (!match) return res.status(401).json({ message: "Invalid credentials" });

	const token = jwt.sign({ user_id: user.id }, JWT_SECRET);
	res.json({ token });
});

// ------------------ PROGRESS APIs ------------------

app.get("/progress", authenticate, (req, res) => {
	const rows = db
		.prepare("SELECT * FROM progress WHERE user_id = ?")
		.all(req.user.id);
	res.json(rows);
});

app.post("/progress", authenticate, (req, res) => {
	try {
		const {
			para,
			completed_pages = 0,
			total_pages,
			start_date = null,
			end_date = null,
		} = req.body;

		const prev = db
			.prepare("SELECT * FROM progress WHERE user_id = ? AND para = ?")
			.get(req.user.id, para);

		db.prepare(
			`INSERT INTO progress (user_id, para, completed_pages, total_pages, start_date, end_date)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(user_id, para) DO UPDATE SET
			 completed_pages = excluded.completed_pages,
			 total_pages = excluded.total_pages,
			 start_date = excluded.start_date,
			 end_date = excluded.end_date`
		).run(
			req.user.id,
			para,
			completed_pages,
			total_pages,
			start_date,
			end_date
		);

		const logStmt = db.prepare(`INSERT INTO activity_log (
			user_id, para, timestamp, updated_field, previous_value, new_value, pages_memorized
		) VALUES (?, ?, ?, ?, ?, ?, ?)`);

		const now = new Date().toLocaleString("sv-SE", {
			timeZone: "Asia/Kolkata",
		});

		if (prev) {
			if (prev.completed_pages !== completed_pages) {
				const diff = completed_pages - prev.completed_pages;
				if (diff !== 0) {
					logStmt.run(
						req.user.id,
						para,
						now,
						"completed_pages",
						`${prev.completed_pages}`,
						`${completed_pages}`,
						diff
					);
				}
			}
			if (prev.total_pages !== total_pages) {
				logStmt.run(
					req.user.id,
					para,
					now,
					"total_pages",
					`${prev.total_pages}`,
					`${total_pages}`,
					null
				);
			}
			if (prev.start_date !== start_date) {
				logStmt.run(
					req.user.id,
					para,
					now,
					"start_date",
					`${prev.start_date}`,
					`${start_date}`,
					null
				);
			}
			if (prev.end_date !== end_date) {
				logStmt.run(
					req.user.id,
					para,
					now,
					"end_date",
					`${prev.end_date}`,
					`${end_date}`,
					null
				);
			}
		}

		res.json({ message: "Progress updated and activity logged" });
	} catch (err) {
		res.status(500).json({ message: "Update failed", error: err.message });
	}
});

// ------------------ Reset All ------------------

app.delete("/reset-all", authenticate, (req, res) => {
	try {
		const reset = db.transaction(() => {
			db.prepare(
				"UPDATE progress SET completed_pages = 0, start_date = NULL, end_date = NULL WHERE user_id = ?"
			).run(req.user.id);
			db.prepare("DELETE FROM activity_log WHERE user_id = ?").run(
				req.user.id
			);
			db.prepare(
				"UPDATE para_surah SET mistakes = 0 WHERE user_id = ?"
			).run(req.user.id);
		});
		reset();
		res.json({ message: "Reset complete" });
	} catch (err) {
		res.status(500).json({ message: "Reset failed", error: err.message });
	}
});

// ------------------ USER APIs ------------------

app.get("/user/me", authenticate, (req, res) => {
	try {
		const user = db
			.prepare(
				"SELECT id, email, role, currentPara FROM users WHERE id = ?"
			)
			.get(req.user.id);

		if (!user) return res.status(401).json({ message: "User not found" });

		res.json({
			id: user.id,
			email: user.email,
			role: user.role,
			currentPara: user.currentPara || null,
		});
	} catch (err) {
		res.status(500).json({
			message: "Failed to fetch user details",
			error: err.message,
		});
	}
});

app.post("/user/updateCurrentPara", authenticate, (req, res) => {
	const { currentPara } = req.body;

	if (!currentPara) {
		return res.status(400).json({ message: "currentPara is required" });
	}

	try {
		db.prepare("UPDATE users SET currentPara = ? WHERE id = ?").run(
			currentPara,
			req.user.id
		);
		res.json({ message: "Current Para updated successfully" });
	} catch (err) {
		res.status(500).json({
			message: "Failed to update currentPara",
			error: err.message,
		});
	}
});

// ------------------ ADMIN ONLY ------------------

app.get("/users", authenticate, (req, res) => {
	try {
		const users = db
			.prepare(
				"SELECT id, full_name, email, currentPara, role, register_date FROM users"
			)
			.all();
		res.json(users);
	} catch (err) {
		res.status(500).json({
			message: "Failed to fetch users",
			error: err.message,
		});
	}
});

// ------------------ para_surah APIs ------------------

// app.get("/para_surah", authenticate, (req, res) => {
// 	try {
// 		const userId = req.user.id;
// 		const rows = db
// 			.prepare(
// 				"SELECT para, surah, page, mistakes FROM para_surah WHERE user_id = ? ORDER BY para, page"
// 			)
// 			.all(userId);

// 		const grouped = {};
// 		for (const row of rows) {
// 			const para = row.para.trim();
// 			if (!grouped[para]) grouped[para] = [];
// 			grouped[para].push({
// 				surah: row.surah,
// 				page: row.page,
// 				mistakes: row.mistakes,
// 			});
// 		}

// 		res.json(grouped);
// 	} catch (err) {
// 		res.status(500).json({
// 			message: "Failed to fetch para_surah data",
// 			error: err.message,
// 		});
// 	}
// });

app.get("/para_surah", authenticate, (req, res) => {
	try {
		const userId = req.user.id;

		// Fetch rows ordered by numeric value of para and then by page
		const rows = db
			.prepare(
				`SELECT para, surah, page, mistakes 
				 FROM para_surah 
				 WHERE user_id = ? 
				 ORDER BY CAST(SUBSTR(para, 6) AS INTEGER), page`
			)
			.all(userId);

		const grouped = {};
		for (const row of rows) {
			const para = row.para.trim();
			if (!grouped[para]) grouped[para] = [];
			grouped[para].push({
				surah: row.surah,
				page: row.page,
				mistakes: row.mistakes,
			});
		}

		// Sort keys: "Para 1" to "Para 30"
		const sortedGrouped = Object.keys(grouped)
			.sort((a, b) => {
				const numA = parseInt(a.replace("Para ", ""));
				const numB = parseInt(b.replace("Para ", ""));
				return numA - numB;
			})
			.reduce((acc, key) => {
				acc[key] = grouped[key];
				return acc;
			}, {});

		res.json(sortedGrouped);
	} catch (err) {
		res.status(500).json({
			message: "Failed to fetch para_surah data",
			error: err.message,
		});
	}
});

app.post("/para_surah", authenticate, (req, res) => {
	const userId = req.user.id;
	const entries = req.body;

	if (!Array.isArray(entries)) {
		return res
			.status(400)
			.json({ message: "Expected an array of entries" });
	}

	const stmt = db.prepare(`
    INSERT INTO para_surah (user_id, para, surah, page, mistakes)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, para, page) DO UPDATE SET
      surah = excluded.surah,
      mistakes = excluded.mistakes
  `);

	const insertMany = db.transaction((rows) => {
		for (const row of rows) {
			stmt.run(userId, row.para, row.surah, row.page, row.mistakes ?? 0);
		}
	});

	try {
		insertMany(entries);
		res.json({ message: "para_surah data inserted/updated successfully" });
	} catch (err) {
		res.status(500).json({
			message: "Failed to insert/update para_surah data",
			error: err.message,
		});
	}
});

app.get("/activities/grouped", (req, res) => {
	try {
		const data = [];
		for (let i = 1; i <= 30; i++) {
			const para = `Para ${i}`;
			const progress = db
				.prepare(
					`
        SELECT start_date, end_date, total_pages, completed_pages
        FROM progress WHERE para = ?
      `
				)
				.get(para);

			const logs = db
				.prepare(
					`
        SELECT timestamp, pages_memorized
        FROM activity_log
        WHERE para = ? AND updated_field = 'completed_pages'
        ORDER BY timestamp ASC
      `
				)
				.all(para);

			data.push({
				para,
				start_date: progress?.start_date || null,
				end_date: progress?.end_date || null,
				total_pages: progress?.total_pages || 0,
				completed_pages: progress?.completed_pages || 0,
				remaining_pages:
					(progress?.total_pages || 0) -
					(progress?.completed_pages || 0),
				logs,
			});
		}
		res.json(data);
	} catch (err) {
		console.error("GET /activities/grouped error:", err);
		res.status(500).json({
			message: "Failed to fetch activities",
			error: err.message,
		});
	}
});

app.delete("/user/:id", authenticate, (req, res) => {
	const userId = req.params.id;

	try {
		const stmt1 = db.prepare("DELETE FROM progress WHERE user_id = ?");
		const result1 = stmt1.run(userId);
		const stmt2 = db.prepare("DELETE FROM para_surah WHERE user_id = ?");
		const result2 = stmt2.run(userId);
		const stmt3 = db.prepare("DELETE FROM activity_log WHERE user_id = ?");
		const result3 = stmt3.run(userId);
		const stmt4 = db.prepare("DELETE FROM users WHERE id = ?");
		const result4 = stmt4.run(userId);

		// if (result.changes === 0) {
		// 	return res.status(404).json({ message: "User not found" });
		// }

		res.json({ message: "User deleted successfully" });
	} catch (err) {
		console.error("Error deleting user:", err);
		res.status(500).json({
			message: "Internal server error",
			error: err.message,
		});
	}
});

app.listen(port, () => {
	console.log(`🚀 Server running at http://localhost:${port}`);
});
