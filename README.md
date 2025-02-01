# kkbbs

基于springboot+vue的学习资源分享平台(多人论坛/博客)

又名**知享乐园**
## 客户端体验地址

[客户端体验地址](http://106.53.179.195:8010)

## 概述

该项目旨在用于一个专属开发者的学习资源共享平台，聊天论坛。

**客户端界面演示**

![image](https://github.com/user-attachments/assets/44c31f7a-4bb9-403a-bbc7-338dcd5b5f60)



**功能导图**

![image](https://github.com/user-attachments/assets/1c8a59bb-1932-4994-9d9a-e93d423c3509)




### 快速开始

#### 后端

##### 环境要求

需要jdk1.8+springboot2

##### 前置要求

导入kkbbs.sql

#### 前端

##### 环境要求

node版本在16.xx

分别到客户端和管理端根目录下运行

``` bash
npm install
npm run dev
```

## 修改前端logo
在前端src/views/Layout.vue文件中修改以下代码
```js
const logoInfo = ref([
  {
    letter: "知",
    color: "#3285FF",
  },
  {
    letter: "享",
    color: "#FB3624",
  },
  {
    letter: "乐",
    color: "#FFBA02",
  },
  {
    letter: "园",
    color: "#25B24E",
  },
]);
```

