# -*- coding: utf-8 -*-
"""
共识圈 —— 仿小红书轻社交平台（Flask + SQLAlchemy）
功能：用户注册/登录、发图文动态、点赞/取消点赞、评论、管理员删动态/评论。
数据库自动适配：
  - 本地 / 未配置 DATABASE_URL 时 → SQLite（文件 instance/consensus.db）
  - 配置 DATABASE_URL（如 Render 的 PostgreSQL）时 → 云端共享数据库
所有接口返回 JSON，统一结构 {"ok": bool, ...}。
"""

import os
from datetime import datetime

import secrets
from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

# ---- 数据库 URI：优先用环境变量 DATABASE_URL（Render 提供 PostgreSQL）----
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    # SQLAlchemy 2.x 要求 postgresql:// 前缀
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL:
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
else:
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(INSTANCE_DIR, "consensus.db")

# 管理员账号：用户名 1456232，密码满足 大小写+数字+符号 且 >=12 位
ADMIN_USERNAME = "1456232"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Consen@Circle2026")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
CORS(app, supports_credentials=True)  # 允许前端独立部署时跨域访问
db = SQLAlchemy(app)


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nickname = db.Column(db.String(80))
    avatar_path = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.String(20), nullable=False)


class Token(db.Model):
    __tablename__ = "tokens"
    token = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.String(20), nullable=False)


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    image_path = db.Column(db.String(255))
    created_at = db.Column(db.String(20), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.String(20), nullable=False)


class Like(db.Model):
    __tablename__ = "likes"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.String(20), nullable=False)
    __table_args__ = (db.UniqueConstraint("post_id", "user_id", name="uq_like_post_user"),)


class CommentLike(db.Model):
    __tablename__ = "comment_likes"
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.String(20), nullable=False)
    __table_args__ = (db.UniqueConstraint("comment_id", "user_id", name="uq_cl_comment_user"),)


class ViewHistory(db.Model):
    __tablename__ = "view_history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    created_at = db.Column(db.String(20), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="uq_vh_user_post"),)


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def error(msg, code):
    return jsonify({"ok": False, "msg": msg}), code


def get_current_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        tok = Token.query.filter_by(token=token).first()
        if tok:
            return db.session.get(User, tok.user_id)
    return None


def serialize_user(u):
    return {
        "id": u.id,
        "username": u.username,
        "nickname": u.nickname or u.username,
        "is_admin": bool(u.is_admin),
        "avatar": ("/" + u.avatar_path) if u.avatar_path else None,
    }


def serialize_post(post, uid=None):
    author = db.session.get(User, post.user_id)
    like_count = Like.query.filter_by(post_id=post.id).count()
    comment_count = Comment.query.filter_by(post_id=post.id).count()
    liked = bool(uid and Like.query.filter_by(post_id=post.id, user_id=uid).first())
    return {
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "image": ("/" + post.image_path) if post.image_path else None,
        "author": (author.nickname or author.username) if author else "未知",
        "author_username": author.username if author else "",
        "created_at": post.created_at,
        "like_count": like_count,
        "comment_count": comment_count,
        "liked": liked,
    }


def serialize_comments(post_id, uid=None):
    """把某动态的评论组装成嵌套结构（含点赞数/是否已赞、子回复）。"""
    comments = Comment.query.filter_by(post_id=post_id).all()
    cmap = {}
    for c in comments:
        author = db.session.get(User, c.user_id)
        like_count = CommentLike.query.filter_by(comment_id=c.id).count()
        liked = bool(uid and CommentLike.query.filter_by(comment_id=c.id, user_id=uid).first())
        cmap[c.id] = {
            "id": c.id,
            "content": c.content,
            "parent_id": c.parent_id,
            "author": (author.nickname or author.username) if author else "未知",
            "author_username": author.username if author else "",
            "user_id": c.user_id,
            "created_at": c.created_at,
            "like_count": like_count,
            "liked": liked,
            "replies": [],
        }
    top = []
    for c in comments:
        o = cmap[c.id]
        if c.parent_id and c.parent_id in cmap:
            cmap[c.parent_id]["replies"].append(o)
        else:
            top.append(o)
    return top


def allowed_file(fn):
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXT


# --------------------------------------------------------------------------- #
# 页面
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    # 优先从仓库根目录读取 index.html；不存在时回退到 templates/（兼容旧结构）
    root_html = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(root_html):
        with open(root_html, "r", encoding="utf-8") as f:
            html = f.read()
        # 预览/静态托管时 meta 为 content="mock"，前端走内置演示数据；
        # 由 Flask 托管时在此替换为 content="flask"，让前端改走真实共享后端。
        html = html.replace('name="x-backend" content="mock"',
                            'name="x-backend" content="flask"')
        return Response(html, mimetype="text/html")
    rendered = render_template("index.html")
    return Response(rendered.replace('name="x-backend" content="mock"',
                                    'name="x-backend" content="flask"'),
                    mimetype="text/html")


# --------------------------------------------------------------------------- #
# 认证
# --------------------------------------------------------------------------- #
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return error("用户名和密码不能为空", 400)
    if len(password) < 6:
        return error("密码至少 6 位", 400)
    if User.query.filter_by(username=username).first():
        return error("用户名已存在", 409)
    db.session.add(
        User(
            username=username,
            password_hash=generate_password_hash(password),
            nickname=username,
            is_admin=False,
            created_at=now(),
        )
    )
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return error("用户名或密码错误", 401)
    token = secrets.token_hex(32)
    db.session.add(Token(token=token, user_id=user.id, created_at=now()))
    db.session.commit()
    return jsonify({"ok": True, "token": token, "user": serialize_user(user)})


@app.route("/api/me")
def me():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False})
    return jsonify({"ok": True, "user": serialize_user(user)})


# --------------------------------------------------------------------------- #
# 动态
# --------------------------------------------------------------------------- #
@app.route("/api/posts")
def list_posts():
    page = int(request.args.get("page", 1))
    per_page = 10
    user = get_current_user()
    uid = user.id if user else None
    total = Post.query.count()
    rows = (
        Post.query.order_by(Post.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
        .all()
    )
    posts = [serialize_post(r, uid) for r in rows]
    return jsonify(
        {
            "ok": True,
            "posts": posts,
            "page": page,
            "has_more": page * per_page < total,
        }
    )


@app.route("/api/posts", methods=["POST"])
def create_post():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    title = (request.form.get("title") or "").strip()
    content = (request.form.get("content") or "").strip()
    if not content and not title:
        return error("标题或内容不能为空", 400)
    image_path = None
    f = request.files.get("image")
    if f and f.filename:
        if not allowed_file(f.filename):
            return error("仅支持 png/jpg/jpeg/gif/webp 图片", 400)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        fn = secure_filename(f"{datetime.now().timestamp()}_{f.filename}")
        f.save(os.path.join(UPLOAD_FOLDER, fn))
        image_path = os.path.join("static", "uploads", fn)
    db.session.add(
        Post(
            user_id=user.id,
            title=title,
            content=content,
            image_path=image_path,
            created_at=now(),
        )
    )
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/posts/<int:pid>")
def post_detail(pid):
    user = get_current_user()
    uid = user.id if user else None
    post = db.session.get(Post, pid)
    if not post:
        return error("动态不存在", 404)
    p = serialize_post(post, uid)
    p["comments"] = serialize_comments(pid, uid)
    return jsonify({"ok": True, "post": p})


@app.route("/api/posts/<int:pid>/like", methods=["POST"])
def toggle_like(pid):
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    if not db.session.get(Post, pid):
        return error("动态不存在", 404)
    existing = Like.query.filter_by(post_id=pid, user_id=user.id).first()
    if existing:
        db.session.delete(existing)
        liked = False
    else:
        db.session.add(Like(post_id=pid, user_id=user.id, created_at=now()))
        liked = True
    db.session.commit()
    count = Like.query.filter_by(post_id=pid).count()
    return jsonify({"ok": True, "liked": liked, "like_count": count})


@app.route("/api/posts/<int:pid>/comments", methods=["POST"])
def add_comment(pid):
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    parent_id = data.get("parent_id")
    if not content:
        return error("评论内容不能为空", 400)
    if not db.session.get(Post, pid):
        return error("动态不存在", 404)
    db.session.add(
        Comment(post_id=pid, user_id=user.id, content=content, parent_id=parent_id, created_at=now())
    )
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/posts/<int:pid>", methods=["DELETE"])
def delete_post(pid):
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    if not user.is_admin:
        return error("仅管理员可删除动态", 403)
    post = db.session.get(Post, pid)
    if not post:
        return error("动态不存在", 404)
    if post.image_path:
        try:
            os.remove(os.path.join(BASE_DIR, post.image_path))
        except OSError:
            pass
    Like.query.filter_by(post_id=pid).delete()
    Comment.query.filter_by(post_id=pid).delete()
    db.session.delete(post)
    db.session.commit()
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# 评论删除（仅管理员）
# --------------------------------------------------------------------------- #
@app.route("/api/comments/<int:cid>", methods=["DELETE"])
def delete_comment(cid):
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    if not user.is_admin:
        return error("仅管理员可删除评论", 403)
    comment = db.session.get(Comment, cid)
    if comment:
        db.session.delete(comment)
        db.session.commit()
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# 个人信息 / 我的数据
# --------------------------------------------------------------------------- #
@app.route("/api/me", methods=["POST"])
def update_me():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    nickname = (request.form.get("nickname") or "").strip()
    if nickname:
        user.nickname = nickname
    f = request.files.get("avatar")
    if f and f.filename:
        if not allowed_file(f.filename):
            return error("仅支持 png/jpg/jpeg/gif/webp 图片", 400)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        fn = secure_filename(f"{datetime.now().timestamp()}_avatar_{user.id}_{f.filename}")
        f.save(os.path.join(UPLOAD_FOLDER, fn))
        user.avatar_path = os.path.join("static", "uploads", fn)
    db.session.commit()
    return jsonify({"ok": True, "user": serialize_user(user)})


@app.route("/api/me/likes")
def me_likes():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    rows = (
        db.session.query(Post)
        .join(Like, Like.post_id == Post.id)
        .filter(Like.user_id == user.id)
        .order_by(Post.id.desc())
        .all()
    )
    return jsonify({"ok": True, "posts": [serialize_post(p, user.id) for p in rows]})


@app.route("/api/me/comments")
def me_comments():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    rows = (
        db.session.query(Comment, Post)
        .join(Post, Post.id == Comment.post_id)
        .filter(Comment.user_id == user.id)
        .order_by(Comment.id.desc())
        .all()
    )
    data = [
        {
            "id": c.id,
            "content": c.content,
            "post_id": c.post_id,
            "post_title": p.title or "(无标题)",
            "created_at": c.created_at,
        }
        for c, p in rows
    ]
    return jsonify({"ok": True, "comments": data})


@app.route("/api/me/posts")
def me_posts():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    rows = Post.query.filter_by(user_id=user.id).order_by(Post.id.desc()).all()
    return jsonify({"ok": True, "posts": [serialize_post(p, user.id) for p in rows]})


@app.route("/api/posts/<int:pid>/view", methods=["POST"])
def record_view(pid):
    """记录浏览历史：登录用户打开动态详情时调用。同一用户同一动态只保留最新一条。"""
    user = get_current_user()
    if not user:
        return jsonify({"ok": True})  # 未登录不记录，但不报错
    if not db.session.get(Post, pid):
        return error("动态不存在", 404)
    existing = ViewHistory.query.filter_by(user_id=user.id, post_id=pid).first()
    if existing:
        existing.created_at = now()
    else:
        db.session.add(ViewHistory(user_id=user.id, post_id=pid, created_at=now()))
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/me/history")
def me_history():
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    rows = (
        ViewHistory.query.filter_by(user_id=user.id)
        .order_by(ViewHistory.created_at.desc())
        .all()
    )
    seen = set()
    out = []
    for v in rows:
        if v.post_id in seen:
            continue
        seen.add(v.post_id)
        p = db.session.get(Post, v.post_id)
        if not p:
            continue
        item = serialize_post(p, user.id)
        item["viewed_at"] = v.created_at
        out.append(item)
    return jsonify({"ok": True, "posts": out})


@app.route("/api/comments/<int:cid>/like", methods=["POST"])
def like_comment(cid):
    user = get_current_user()
    if not user:
        return error("请先登录", 401)
    if not db.session.get(Comment, cid):
        return error("评论不存在", 404)
    existing = CommentLike.query.filter_by(comment_id=cid, user_id=user.id).first()
    if existing:
        db.session.delete(existing)
        liked = False
    else:
        db.session.add(CommentLike(comment_id=cid, user_id=user.id, created_at=now()))
        liked = True
    db.session.commit()
    count = CommentLike.query.filter_by(comment_id=cid).count()
    return jsonify({"ok": True, "liked": liked, "like_count": count})


# --------------------------------------------------------------------------- #
# 清理重复动态（仅管理员）：同一作者 + 标题 + 内容 完全相同者，仅保留最早一条
# --------------------------------------------------------------------------- #
@app.route("/api/admin/dedupe", methods=["POST"])
def dedupe_posts():
    user = get_current_user()
    if not user or not user.is_admin:
        return error("仅管理员可操作", 403)
    seen = {}
    removed = 0
    for p in Post.query.order_by(Post.id.asc()).all():
        key = (p.user_id, p.title, p.content)
        if key in seen:
            Like.query.filter_by(post_id=p.id).delete()
            Comment.query.filter_by(post_id=p.id).delete()
            db.session.delete(p)
            removed += 1
        else:
            seen[key] = p.id
    db.session.commit()
    return jsonify({"ok": True, "removed": removed})


# --------------------------------------------------------------------------- #
# 初始化（建表 + 创建管理员）
# --------------------------------------------------------------------------- #
def migrate_db():
    """在已有库上补列/建新表（create_all 不会 ALTER 已存在表）。幂等，可重复执行。"""
    insp = inspect(db.engine)
    try:
        user_cols = {c["name"] for c in insp.get_columns("users")}
    except Exception:
        user_cols = set()
    if "avatar_path" not in user_cols:
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN avatar_path VARCHAR(255)"))
                conn.commit()
        except Exception:
            pass
    try:
        cmt_cols = {c["name"] for c in insp.get_columns("comments")}
    except Exception:
        cmt_cols = set()
    if "parent_id" not in cmt_cols:
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE comments ADD COLUMN parent_id INTEGER"))
                conn.commit()
        except Exception:
            pass
    try:
        tables = set(insp.get_table_names())
    except Exception:
        tables = set()
    if "comment_likes" not in tables:
        try:
            CommentLike.__table__.create(db.engine, checkfirst=True)
        except Exception:
            pass
    if "view_history" not in tables:
        try:
            ViewHistory.__table__.create(db.engine, checkfirst=True)
        except Exception:
            pass


def init_db():
    with app.app_context():
        db.create_all()
        migrate_db()
        admin = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not admin:
            admin = User(username=ADMIN_USERNAME, nickname="管理员",
                         is_admin=True, created_at=now())
            db.session.add(admin)
        # 强制把管理员密码同步为当前 ADMIN_PASSWORD（无论是否已存在，
        # 避免环境变量变更后数据库里的旧密码导致登录不上）
        admin.password_hash = generate_password_hash(ADMIN_PASSWORD)
        # 演示用户（密码统一 123456）
        demo_users = [("xiaomei", "小美"), ("dazhi", "大志"), ("achao", "阿超")]
        demo_map = {}
        for uname, nick in demo_users:
            u = User.query.filter_by(username=uname).first()
            if not u:
                u = User(username=uname, password_hash=generate_password_hash("123456"),
                         nickname=nick, is_admin=False, created_at=now())
                db.session.add(u)
                db.session.flush()
            demo_map[uname] = u
        db.session.commit()
        # 演示动态（仅演示数据尚未存在时填充，避免多 worker 并发重复 seed）
        if Post.query.filter_by(title="周末citywalk路线分享").first() is None:
            samples = [
                ("xiaomei", "周末citywalk路线分享", "沿着梧桐区慢慢走，咖啡店、二手书店、小画廊一路逛下来，整个人都松弛了。附上我的私藏打卡点～"),
                ("xiaomei", "今日妆容 | 伪素颜通勤", "底妆只用了气垫+散粉，眉毛野生感，唇釉选了奶茶色，5分钟出门。"),
                ("dazhi", "自己做的低卡晚餐", "西兰花虾仁+半根玉米+一小碗藜麦，饱腹又没负担，减脂期也能吃得很满足。"),
                ("dazhi", "读书笔记《被讨厌的勇气》", "课题分离真的太重要了。别人的评价是别人的课题，我只需要对自己的选择负责。"),
                ("achao", "阳台改造计划", "把杂物间清空，铺了木地板，摆上躺椅和绿植，现在这里是我每天最想待的角落。"),
                ("achao", "通勤路上拍到的晚霞", "下班那刻天空是橘子味的，疲惫瞬间被治愈。"),
                ("xiaomei", "新手瑜伽第30天", "终于能稳稳下犬式了，身体变轻了，睡眠也好了很多。"),
                ("dazhi", "一人食火锅教程", "清汤底+肥牛+蔬菜拼盘，蘸料是蒜泥香油，简单又幸福。"),
            ]
            for uname, title, content in samples:
                u = demo_map.get(uname)
                if u:
                    db.session.add(Post(user_id=u.id, title=title, content=content,
                                        image_path=None, created_at=now()))
            db.session.commit()


# 导入即初始化数据库（gunicorn / flask run 都会执行）
init_db()

if __name__ == "__main__":
    init_db()
    print("=" * 48)
    print("  共识圈 启动成功")
    print("  管理员账号 :", ADMIN_USERNAME)
    print("  管理员密码 :", ADMIN_PASSWORD)
    print("  数据库     :", "PostgreSQL" if DATABASE_URL else "SQLite (本地)")
    print("  访问地址   : http://localhost:5000")
    print("=" * 48)
    app.run(host="0.0.0.0", port=5000, debug=True)
