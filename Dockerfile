# استخدم Node.js الرسمي
FROM node:20-alpine

# تحديد مجلد العمل
WORKDIR /index

# نسخ ملفات المشروع
COPY package*.json ./
COPY . .

# تثبيت الحزم
RUN npm install

# بناء المشروع (لو React أو أي فرونت إند)
RUN npm run build

# تحديد البورت
ENV PORT=3000
EXPOSE 3000

# تشغيل المشروع
CMD ["npm", "start"]
