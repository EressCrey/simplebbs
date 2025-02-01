/*
 Navicat Premium Data Transfer

 Source Server         : 本机MySQL
 Source Server Type    : MySQL
 Source Server Version : 50719 (5.7.19)
 Source Host           : localhost:3306
 Source Schema         : easybbs

 Target Server Type    : MySQL
 Target Server Version : 50719 (5.7.19)
 File Encoding         : 65001

 Date: 25/11/2024 10:53:31
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for email_code
-- ----------------------------
DROP TABLE IF EXISTS `email_code`;
CREATE TABLE `email_code`  (
  `email` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '邮箱',
  `code` varchar(5) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '编号',
  `create_time` datetime NULL DEFAULT NULL COMMENT '创建时间',
  `status` tinyint(1) NULL DEFAULT NULL COMMENT '0:未使用  1:已使用',
  PRIMARY KEY (`email`, `code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '邮箱验证码' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of email_code
-- ----------------------------
INSERT INTO `email_code` VALUES ('2629152500@qq.com', '34960', '2024-04-16 15:41:11', 1);
INSERT INTO `email_code` VALUES ('2661727280@qq.com', '16872', '2024-04-08 19:38:30', 1);
INSERT INTO `email_code` VALUES ('2661727280@qq.com', '29153', '2023-11-15 21:51:54', 1);
INSERT INTO `email_code` VALUES ('2661727280@qq.com', '73275', '2024-03-11 15:08:08', 1);
INSERT INTO `email_code` VALUES ('2765314967@qq.com', '07012', '2024-03-11 15:02:07', 1);
INSERT INTO `email_code` VALUES ('2765314967@qq.com', '30668', '2024-04-03 18:23:16', 1);
INSERT INTO `email_code` VALUES ('2765314967@qq.com', '37835', '2023-11-07 21:55:37', 1);
INSERT INTO `email_code` VALUES ('2935406165@qq.com', '66684', '2023-11-21 18:55:35', 1);
INSERT INTO `email_code` VALUES ('3222723170@qq.com', '80323', '2023-11-19 15:30:52', 1);
INSERT INTO `email_code` VALUES ('3641807404@qq.com', '47559', '2024-04-16 11:30:01', 0);
INSERT INTO `email_code` VALUES ('3641807404@qq.com', '75434', '2024-04-16 11:28:50', 1);
INSERT INTO `email_code` VALUES ('test02@qq.com', '02758', '2023-01-16 09:38:44', 1);
INSERT INTO `email_code` VALUES ('test@qq.com', '08531', '2023-01-15 17:45:44', 1);
INSERT INTO `email_code` VALUES ('tmpwiHXtitJDHH3FrJ@dreamhunter2333.xyz', '06644', '2024-04-03 19:07:56', 1);
INSERT INTO `email_code` VALUES ('tmpwiHXtitJDHH3FrJ@dreamhunter2333.xyz', '38061', '2024-04-03 19:08:46', 0);

-- ----------------------------
-- Table structure for forum_article
-- ----------------------------
DROP TABLE IF EXISTS `forum_article`;
CREATE TABLE `forum_article`  (
  `article_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文章ID',
  `board_id` int(11) NULL DEFAULT NULL COMMENT '板块ID',
  `board_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '板块名称',
  `p_board_id` int(11) NULL DEFAULT NULL COMMENT '父级板块ID',
  `p_board_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '父板块名称',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户ID',
  `nick_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '昵称',
  `user_ip_address` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '最后登录ip地址',
  `title` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '标题',
  `cover` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '封面',
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '内容',
  `markdown_content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT 'markdown内容',
  `editor_type` tinyint(4) NOT NULL COMMENT '0:富文本编辑器 1:markdown编辑器',
  `summary` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '摘要',
  `post_time` datetime NOT NULL COMMENT '发布时间',
  `last_update_time` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间',
  `read_count` int(11) NULL DEFAULT 0 COMMENT '阅读数量',
  `good_count` int(11) NULL DEFAULT 0 COMMENT '点赞数',
  `comment_count` int(11) NULL DEFAULT 0 COMMENT '评论数',
  `top_type` tinyint(4) NULL DEFAULT 0 COMMENT '0未置顶  1:已置顶',
  `attachment_type` tinyint(4) NULL DEFAULT NULL COMMENT '0:没有附件  1:有附件',
  `status` tinyint(4) NULL DEFAULT NULL COMMENT '-1已删除 0:待审核  1:已审核 ',
  PRIMARY KEY (`article_id`) USING BTREE,
  INDEX `idx_board_id`(`board_id`) USING BTREE,
  INDEX `idx_pboard_id`(`p_board_id`) USING BTREE,
  INDEX `idx_post_time`(`post_time`) USING BTREE,
  INDEX `idx_top_type`(`top_type`) USING BTREE,
  INDEX `idx_title`(`title`) USING BTREE,
  INDEX `idx_user_id`(`user_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '文章信息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of forum_article
-- ----------------------------
INSERT INTO `forum_article` VALUES ('0XHRpvcW13aTVMu', 0, '', 10001, '后端', '6783480097', 'kkk', '江西省', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', '202404/6hVOtq0eLHCPMTc.jpg', '<h1>目录</h1><h2>文章目录</h2><p>📑前言</p><p>**目录**</p><h2>一、介绍</h2><h2>二、主要功能</h2><h2>三、原理</h2><h3>1. SpringSecurity 过滤器链</h3><h3>2. JWT校验登录的校验流程</h3><h2>四、Spring Boot整合Redis、SpringSecurity、JWT的示例demo</h2><p>📑文章末尾</p><p>Spring Security</p><p><br></p><h2>一、介绍</h2><p>Spring Security是一个强大且高度可定制的身份验证和访问控制框架。它是保护基于Spring的应用程序的实际标准。Spring Security是一个可以为Java应用程序提供全面安全服务的框架。同时，它也可以轻松扩展以满足自定义需求。</p><p><br></p><h2>二、主要功能</h2><p>Authentication (认证)，就是用户登录</p><p>Authorization (授权)：一旦身份验证成功，判断用户拥有什么权限，可以访问什么资源</p><p>防止跨站请求伪造（CSRF）：Spring Security提供了内置的防护机制，可以防止跨站请求伪造攻击。</p><p>密码存储：Spring Security提供了多种密码存储格式，包括明文、加密和哈希。</p><p>集成其他安全框架：Spring Security可以与其他安全框架如OAuth2、JWT等进行集成，以提供更全面的安全解决方案。</p><p><br></p><h2>三、原理</h2><p>​ SpringSecurity的原理其实就是一个过滤器链，内部包含了提供各种功能的过滤器。</p><p><br></p><h3>1. SpringSecurity 过滤器链</h3><p>SpringSecurity 采用的是责任链的设计模式，它有一条很长的过滤器链。</p><p>SecurityContextPersistenceFilter：每次请求处理之前将该请求相关的安全上下文信息加载到 SecurityContextHolder 中。</p><p>LogoutFilter：用于处理退出登录。</p><p>UsernamePasswordAuthenticationFilter：用于处理基于表单的登录请求，从表单中获取用户名和密码。</p><p>BasicAuthenticationFilter：检测和处理 http basic 认证。</p><p>ExceptionTranslationFilter：处理过滤器链中抛出的任何AccessDeniedException和AuthenticationException 。</p><p>FilterSecurityInterceptor：负责权限校验的过滤器，可以看做过滤器链的出口。</p><p>…</p><p>流程说明:客户端发起一个请求，进入 Security 过滤器链。</p><p>1.当到 LogoutFilter 的时候判断是否是登出路径，如果是登出路径则到 logoutHandler ，如果登出成功则到logoutSuccessHandler 登出成功处理，如果登出失败则由 ExceptionTranslationFilter ；如果不是登出路径则直接进入下一个过滤器。</p><p>2.当到 UsernamePasswordAuthenticationFilter 的时候判断是否为登录路径，如果是，则进入该过滤器进行登录操作，如果登录失败则到 AuthenticationFailureHandler 登录失败处理器处理，如果登录成功则到 AuthenticationSuccessHandler 登录成功处理器处理，如果不是登录请求则不进入该过滤器。</p><p>3.当到 FilterSecurityInterceptor 的时候会拿到 uri ，根据 uri 去找对应的鉴权管理器，鉴权管理器做鉴权工作，鉴权成功则到 Controller 层否则到 AccessDeniedHandler 鉴权失败处理器处理。</p><p>2. JWT校验登录的校验流程</p><p>首先前端一样是把登录信息发送给后端，后端查询数据库校验用户的账号和密码是否正确，正确的话则使用jwt生成token，并且返回给前端。以后前端每次请求时，都需要携带token，后端获取token后，使用jwt进行验证用户的token是否无效或过期，验证成功后才去做相应的逻辑。</p><h2>四、Spring Boot整合Redis、SpringSecurity、JWT的示例demo</h2><p>添加依赖项在 pom.xml 文件中添加以下依赖项：</p><pre><code >   &lt;dependencies&gt;\r\n    &lt;dependency&gt;\r\n        &lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;\r\n        &lt;artifactId&gt;spring-boot-starter-data-redis&lt;/artifactId&gt;\r\n    &lt;/dependency&gt;\r\n    &lt;dependency&gt;\r\n        &lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;\r\n        &lt;artifactId&gt;spring-boot-starter-security&lt;/artifactId&gt;\r\n    &lt;/dependency&gt;\r\n    &lt;dependency&gt;\r\n        &lt;groupId&gt;io.jsonwebtoken&lt;/groupId&gt;\r\n        &lt;artifactId&gt;jjwt&lt;/artifactId&gt;\r\n        &lt;version&gt;0.9.1&lt;/version&gt;\r\n    &lt;/dependency&gt;\r\n&lt;/dependencies&gt;`</code></pre><p>创建Redis配置类</p><pre><code class=\"language-java\">@Configuration\r\npublic class RedisConfig {\r\n    @Value(\"${spring.redis.host}\")\r\n    private String host;\r\n    @Value(\"${spring.redis.port}\")\r\n    private int port;\r\n    @Bean\r\n    public JedisConnectionFactory jedisConnectionFactory() {\r\n        return new JedisConnectionFactory(new RedisStandaloneConfiguration(host, port));\r\n    }\r\n    @Bean\r\n    public RedisTemplate&lt;String, Object&gt; redisTemplate() {\r\n        final RedisTemplate&lt;String, Object&gt; template = new RedisTemplate&lt;&gt;();\r\n        template.setConnectionFactory(jedisConnectionFactory());\r\n        return template;\r\n    }\r\n}</code></pre><p>创建 JwtTokenUtil 类，用于生成和验证JWT令牌。</p><pre><code class=\"language-java\">@Component\r\npublic class JwtTokenUtil implements Serializable {\r\n    private static final long serialVersionUID = -2550185165626007488L;\r\n    private static final String secret = \"mySecret\";\r\n    public String getUsernameFromToken(String token) {\r\n        return getClaimFromToken(token, Claims::getSubject);\r\n    }\r\n    public Date getExpirationDateFromToken(String token) {\r\n        return getClaimFromToken(token, Claims::getExpiration);\r\n    }\r\n    public &lt;T&gt; T getClaimFromToken(String token, Function&lt;Claims, T&gt; claimsResolver) {\r\n        final Claims claims = getAllClaimsFromToken(token);\r\n        return claimsResolver.apply(claims);\r\n    }\r\n    private Claims getAllClaimsFromToken(String token) {\r\n        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();\r\n    }\r\n    private Boolean isTokenExpired(String token) {\r\n        final Date expiration = getExpirationDateFromToken(token);\r\n        return expiration.before(new Date());\r\n    }\r\n    public String generateToken(UserDetails userDetails) {\r\n        Map&lt;String, Object&gt; claims = new HashMap&lt;&gt;();\r\n        return doGenerateToken(claims, userDetails.getUsername());\r\n    }\r\n    private String doGenerateToken(Map&lt;String, Object&gt; claims, String subject) {\r\n        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))\r\n                .setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 60 * 1000))\r\n                .signWith(SignatureAlgorithm.HS512, secret).compact();\r\n    }\r\n    public Boolean validateToken(String token, UserDetails userDetails) {\r\n        final String username = getUsernameFromToken(token);\r\n        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));\r\n    }</code></pre><h4>创建 JwtAuthenticationEntryPoint 类，用于处理未经授权的请求。</h4><pre><code class=\"language-java\">@Component\r\npublic class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {\r\n    private static final long serialVersionUID = -7858869558953243875L;\r\n    @Override\r\n    public void commence(HttpServletRequest request, HttpServletResponse response,\r\n                         AuthenticationException authException) throws IOException {\r\n        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, \"Unauthorized\");\r\n    }\r\n}` </code></pre><h4>创建 JwtRequestFilter 类，用于解析和验证JWT令牌。</h4><pre><code class=\"language-java\">@Component\r\npublic class JwtRequestFilter extends OncePerRequestFilter {\r\n    @Autowired\r\n    private MyUserDetailsService myUserDetailsService;\r\n    @Autowired\r\n    private JwtTokenUtil jwtTokenUtil;\r\n    @Override\r\n    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)\r\n            throws ServletException, IOException {\r\n        final String requestTokenHeader = request.getHeader(\"Authorization\");\r\n        String username = null;\r\n        String jwtToken = null;\r\n        if (requestTokenHeader != null && requestTokenHeader.startsWith(\"Bearer \")) {\r\n            jwtToken = requestTokenHeader.substring(7);\r\n            try {\r\n                username = jwtTokenUtil.getUsernameFromToken(jwtToken);\r\n            } catch (IllegalArgumentException e) {\r\n                System.out.println(\"Unable to get JWT Token\");\r\n            } catch (ExpiredJwtException e) {\r\n                System.out.println(\"JWT Token has expired\");\r\n            }\r\n        } else {\r\n            logger.warn(\"JWT Token does not begin with Bearer String\");\r\n        }\r\n        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {\r\n            UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);\r\n            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {\r\n                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(\r\n                        userDetails, null, userDetails.getAuthorities());\r\n                usernamePasswordAuthenticationToken\r\n                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));\r\n                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);\r\n            }\r\n        }\r\n        chain.doFilter(request, response);\r\n    }\r\n}` </code></pre><p>配置Spring Security</p><pre><code class=\"language-java\">@Configuration\r\n@EnableWebSecurity\r\npublic class WebSecurityConfig extends WebSecurityConfigurerAdapter {\r\n    @Autowired\r\n    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;\r\n    @Autowired\r\n    private UserDetailsService jwtUserDetailsService;\r\n    @Autowired\r\n    private JwtRequestFilter jwtRequestFilter;\r\n    @Autowired\r\n    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {\r\n        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());\r\n    }\r\n    @Bean\r\n    public PasswordEncoder passwordEncoder() {\r\n        return new BCryptPasswordEncoder();\r\n    }\r\n    @Bean\r\n    @Override\r\n    public AuthenticationManager authenticationManagerBean() throws Exception {\r\n        return super.authenticationManagerBean();\r\n    }\r\n    @Override\r\n    protected void configure(HttpSecurity httpSecurity) throws Exception {\r\n        httpSecurity.csrf().disable()\r\n                .authorizeRequests().antMatchers(\"/authenticate\").permitAll().\r\n                        anyRequest().authenticated().and().\r\n                        exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()\r\n                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);\r\n        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);\r\n    }\r\n}`</code></pre><p>以上是简单的Spring Boot整合Redis、Security、JWT和Redis的示例，可以根据自己的实际需求进行调整。</p><p><br></p>', '', 0, '', '2023-11-14 21:06:49', '2024-09-23 13:24:14', 181, 4, 11, 0, 1, 1);
INSERT INTO `forum_article` VALUES ('a7W76KbZasuNhXK', 0, '', 10011, '数据结构', '3764947030', '80323', '江西省', '二叉树定义', '202404/XT6KYhUMlNtTmrq.jpg', '<p>树的介绍</p><p>树的定义</p><p>树是由n(n&gt;=0)个节点组成的有限集合。如果n=0,称为空树；如果n&gt;0,则：</p><p>有一个特定的称之为根（root）的节点，它只有直接后继，但没有直接前驱；</p><p>除根以外的其它节点划分为m(m&gt;=0)个互不相交的有限集合，每个集合又是一棵树，并且称之为根的子树，没棵子树的根节点有且只有一个直接前驱，但可以有0个或多个直接后继</p><p><img src=\"/api/file/getImage/202311/Qacp3Kq1HH8m47ZAxOEBKwjKu4Mvkv.png\" alt=\"\" data-href=\"\" style=\"\"/></p><p>树的性质：</p><p>节点的度：一个节点含有的子树的个数称为该节点的度；</p><p>树的度：一棵树中，最大的节点的度称为树的度（这里不一定是根节点,如：A的度为2，C的度为3，那么这棵树的度就位3）</p><p>叶节点或终端节点的度为0</p><p>非终端节点/分支节点是度不为0的节点</p><p>父亲节点:若一个接地那还有子节点，则这个节点称为其子节点的父节点</p><p>孩子节点：一个节点含有的子树的根节点称为该节点的子节点</p><p>兄弟节点：具有相同父节点的节点互称为兄弟节点</p><p>节点的层次：从根开始定义起，根为第一层，根的子节点为第2层，以此类推</p><p>深度：对于任意节点n,n的深度为从根到n的唯一路径长，跟的深度为0</p><p>高度：对于任意节点n,n的高度为从n到一片树叶的最长路径长，所有的树叶的高度为0</p><p>堂兄弟节点：父节点在同一层的节点互称为堂兄弟</p><p>节点的祖先：从根到该节点所经分支的所有节点</p><p>子孙：以某节点为根的子树中任一节点都称为该节点的子孙</p><p>森林：由m(m&gt;=0)棵互不相交的树称为森林</p><p>树中任意节点的子节点之间没有顺序关系，这种树称为无序树，也称为自由树。反之是有序树</p><p>二叉树</p><p>二叉树的定义</p><p>所谓二叉树，即一棵只有两个分叉的树，每个节点最多有2个子树。他有五种形态：</p><p> 二叉树与度为2的树的区别</p><p>二叉树的度不一定为2，比如只存在左子树或者右子树</p><p>二叉树的树可以为空，但是度为2的树至少有一个节点含有两个子树</p><p>二叉树的性质</p><p>若二叉树的层次从0开始，则在二叉树的第i层最多有2^i个节点。(i&gt;=0)</p><p>高度为k的二叉树最多有2^(k+1)-1个节点（k&gt;=0）</p><p>对于任何一棵二叉树，如果其叶节点个数为n0,度为2的非节点个数为n2，则有n0=n2+1</p><p>包含n个节点的二叉树的高度至少为log2(n+1)</p><p>二叉树的种类</p><p>满二叉树：每一层的节点数均达到最大值</p><p>完全二叉树：除最后一层之外，其它层均达到了最大值，并且最后一层是从右向左依次进行缺省（满二叉树是一种特殊的完全二叉树）</p><p>注意：左右是满二叉树，但整体不一定是满二叉树，同样，左右子树是完全二叉树，但整体不一定是完全二叉树，如图：</p><p>二叉树的存储方式</p><p>顺序存储</p><p>顺序存储就是用数组来存储，如图：</p><p><img src=\"/api/file/getImage/202311/Nak0fHMMO7xYS0dtcDuSn1Al2uZzCF.png\" alt=\"\" data-href=\"\" style=\"\"/></p><p> 由图看出：当二叉树不为完全二叉树时，容易造成空间浪费</p><p>链式存储</p><p>链式存储就是通过指针把散落的地址穿起来，如图：</p><p>静态存储</p>', '', 0, '', '2023-11-19 15:45:23', '2024-07-14 15:52:25', 12, 0, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('AXY6tGgAKwOUBEn', 0, '', 10028, '知享社区', '3159491214', '念', '江西省', '大家平时都是怎么学习的？', '202311/YKZjiS2hS60p5p6.jpg', '<p>大家平时都是怎么学习的？</p>', NULL, 0, NULL, '2023-11-21 19:04:31', '2024-09-23 13:24:13', 22, 1, 2, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('aYa8yjvk4fxMbYM', 0, '', 10028, '知享社区', '6783480097', 'kkk', '江西省', '请大家规范乐园制度!', '202404/cPjrSRGB8k2xGwZ.jpg', '<p>请大家规范乐园制度!</p>', '', 0, '请大家规范乐园制度!', '2023-11-21 20:07:21', '2024-11-22 09:53:33', 54, 0, 3, 1, 1, 1);
INSERT INTO `forum_article` VALUES ('bEEIzLEU5STfoRt', 10010, 'java', 10001, '后端', '6783480097', 'kkk', '江西省', '测试文章', '202404/GpJeXGXjV1r8qSG.png', '<p>这是一个测试贴</p>', '', 0, '6666', '2023-11-21 19:27:16', '2024-04-17 21:05:08', 9, 1, 1, 0, 1, 1);
INSERT INTO `forum_article` VALUES ('CPWUe9ujqFHjthh', 0, '', 10000, '前端', '7430015025', 'kkky', '江西省', 'Web Worker的概念、用法、使用场景', '202311/iF6moX1QWxgYect.jpg', '<p>1. 简介</p><p>Web Worker 使得在一个独立于 Web 应用程序主执行线程的后台线程中运行脚本操作成为可能。这样做的好处是可以在独立线程中执行费时的处理任务，使主线程（通常是 UI 线程）的运行不会被阻塞/放慢。</p><p>2. 适用场景</p><p>2.1 复杂计算</p><p>当涉及到大量计算或复杂的数据处理时，可以将这些操作放在 Web Worker 中进行，避免阻塞主线程。例如，图像处理、音频处理、视频处理等。</p><p>2.2 后台下载</p><p>当需要下载大量数据时，可以使用 Web Worker 在后台进行数据的下载和处理，以避免阻塞用户界面。例如，从服务器获取大量数据并进行处理之后再展示给用户。</p><p>2.3 数据处理</p><p>当需要对大量数据进行处理或者排序时，可以使用 Web Worker 将处理逻辑放在后台线程中进行，提高处理的效率。</p><p>2.4 实时通信</p><p>可以使用 Web Worker 来处理实时通信的逻辑。在主线程可以与 Web Worker 进行通信，从而实现实时的数据交换。</p><p>3. 代码示例</p><p>3.1 Worker特性检测</p><p>因部分浏览器可能不支持Worker特性，所以为了更好的向下兼容，可以将你的 worker 运行代码包裹在以下代码中（如App.js）：</p><p>if (window.Worker) {</p><p> &nbsp; // 说明当前浏览器支持使用Worker特性</p><p> &nbsp; // TODO 可初始化Worker</p><p>} else {</p><p> &nbsp; // TODO 做其他兼容性处理 </p><p>}</p><p>3.2 Worker API</p><p>Worker 接口是 API 的一部分，指的是一种可由脚本创建的后台任务，任务执行中可以向其创建者收发信息。要创建一个 Worker，只须调用 Worker(URL) 构造函数，函数参数 URL 为指定的脚本。</p><p>Worker 也可以创建新的 Worker，当然，所有 Worker 必须与其创建者同源。</p><p>支持浏览器：</p><p>3.3 SharedWorker API</p><p>SharedWorker 接口代表一种特定类型的 worker，可以从几个浏览上下文中访问，例如几个窗口、iframe 或其他 worker。它们实现一个不同于普通 worker 的接口，具有不同的全局作用域。</p><p>注意： 如果要使 SharedWorker 连接到多个不同的页面，这些页面必须是同源的（相同的协议、host 以及端口）)</p><p>支持浏览器：</p><p>3.4 创建 JavaScript 文件</p><p>首先，我们创建一个名为worker.js的文件，比如用来处理网络数据。worker.js将接收到的数据进行处理，并将处理后的结果发送回主线程。</p><p>// 监听消息事件</p><p>onmessage = (e) =&gt; {</p><p> &nbsp;// 获取传递的数据</p><p> &nbsp;const data = e.data;</p><p> &nbsp;// TODO 在此处进行数据的处理,并返回结果</p><p> &nbsp;// 模拟数据处理</p><p> &nbsp;setTimeout(() =&gt; { &nbsp; &nbsp;</p><p> &nbsp; &nbsp;// 将处理结果发送给主线程</p><p> &nbsp; &nbsp;postMessage(data);</p><p> &nbsp;}, 1000);</p><p>};</p><p>3.5 创建 Web Worker</p><p>在主线程的App.js中，我们仍然使用了useState和useEffect来管理组件的状态和副作用。在useEffect中，我们创建了Web Worker的实例，并使用onmessage来监听Worker发送的消息。当Worker发送消息时，我们更新组件的结果状态。在组件卸载时，我们终止了Worker实例的运行。在按钮的点击事件中，我们使用worker.postMessage方法向Worker发送数据以进行处理。当Worker返回结果时，我们可以在组件中显示它.</p><p>import React, { useState, useEffect, useRef } from \'react\';</p><p>function App() {</p><p> &nbsp;const [result, setResult] = useState(null);</p><p> &nbsp;const workerRef = useRef(null);</p><p> &nbsp;useEffect(() =&gt; {</p><p> &nbsp; &nbsp;// 创建Web Worker实例</p><p> &nbsp; &nbsp;workerRef.current = new Worker(\'worker.js\');</p><p> </p><p> &nbsp; &nbsp;// 监听Worker的消息事件</p><p> &nbsp; &nbsp;workerRef?.current?.onmessage = (e) =&gt; {</p><p> &nbsp; &nbsp; &nbsp;// 接收到Worker的消息</p><p> &nbsp; &nbsp; &nbsp;setResult(e.data);</p><p> &nbsp; &nbsp;};</p><p> &nbsp; &nbsp;return () =&gt; {</p><p> &nbsp; &nbsp; &nbsp;// 组件卸载时，终止Worker实例</p><p> &nbsp; &nbsp; &nbsp;workerRef?.current?.terminate();</p><p> &nbsp; &nbsp;};</p><p> &nbsp;}, []);</p><p> &nbsp;const handleClick = () =&gt; {</p><p> &nbsp; &nbsp;// 启动Worker，并传递数据</p><p> &nbsp; &nbsp;workerRef?.current?.postMessage(\'Data to be processed\');</p><p> &nbsp;};</p><p> &nbsp;return (</p><p> &nbsp; &nbsp;&lt;div&gt;</p><p> &nbsp; &nbsp; &nbsp;&lt;button onClick={handleClick}&gt;Start Processing&lt;/button&gt;</p><p> &nbsp; &nbsp; &nbsp;&lt;div&gt;{result}&lt;/div&gt;</p><p> &nbsp; &nbsp;&lt;/div&gt;</p><p> &nbsp;);</p><p>}</p><p>export default App;</p><p>4. 总结</p><p>通过以上的示例，您创建了一个名为 worker.js 的 JavaScript 文件，并使用 new Worker() 方法在主线程中创建了一个 Web Worker。主线程通过 worker.postMessage() 向 Web Worker 发送消息，并通过 worker.onmessage 监听从 Web Worker 接收到的消息。在 Web Worker 的代码中，通过 self.postMessage() 将结果发送回主线程，并在主线程中处理和输出结果。</p><p>(如有帮助，请记得点赞三连哦~)</p>', NULL, 0, 'Web Worker 使得在一个独立于 Web 应用程序主执行线程的后台线程中运行脚本操作成为可能。这样做的好处是可以在独立线程中执行费时的处理任务，使主线程（通常是 UI 线程）的运行不会被阻塞/放慢。', '2023-11-18 20:21:43', '2024-04-23 20:25:24', 26, 2, 2, 0, 1, 1);
INSERT INTO `forum_article` VALUES ('CWlNdJywlZSp3R4', 0, '', 10022, '大学生论坛', '6783480097', 'kkk', '江西省', '目录结构测试', '202404/tQEymYKZKxxfFmM.jpg', '<h1>标题一</h1><p>这是一个测试目录结构</p><h2>标题二</h2><p>哈哈哈哈</p><h2>标题三</h2><p>呵呵呵呵</p><h2>标题四</h2><p>啊啊啊啊</p><h3>标题五</h3><p>55555</p><h5>标题六</h5><p>哈哈哈哈哈</p>', NULL, 0, NULL, '2024-04-05 14:09:45', '2024-04-17 21:05:00', 106, 0, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('F799DOp4DbbmjtS', 0, '', 10028, '知享社区', '6783480097', 'kkk', '江西省', '哈哈哈哈哈哈哈哈哈', '202404/nwnY6FMhlY3kYSF.jpg', '<p>哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈哈</p>', NULL, 0, '哈哈哈哈哈哈哈哈哈哈哈', '2024-04-05 01:13:27', '2024-04-16 22:14:09', 4, 1, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('PYjST0gDQMZz4JJ', 0, '', 10009, '人工智能', '3764947030', '80323', '江西省', '大模型会毁了初级程序员 —— 对话图灵奖得主 Joseph Sifakis | 新程序员', '202404/3Nftzjv6RzE38bc.jpg', '<p>【编者按】GPT 系列的面世影响了全世界、各个行业，对于开发者们的感受则最为深切。以 ChatGPT、Github Copilot 为首，各类 AI 编程助手层出不穷。编程范式正在发生前所未有的变化，从汇编到 Java 等高级语言，再到今天以自然语言为特征的 Prompt 工程，编程的门槛进一步降低，让很多开发者也不由得思考，编程的未来究竟会如何演化，在这大模型时代，开发者又该何去何从？基于此，《新程序员 007：大模型时代的开发者》邀请到图灵奖得主、中美法三国院士 Joseph Sifakis 进行深度对话。万字长文，感受对人工智能的深邃思考。</p><p>注：《新程序员 007》聚焦开发者成长，其间既有图灵奖得主 Joseph Sifakis、前 OpenAI 科学家 Joel Lehman 等高瞻远瞩，又有对于开发者们至关重要的成长路径、工程实践及趟坑经验等，欢迎大家点击订阅年卡。</p><p>采访 | 邹欣，CSDN &《新程序员》首席内容顾问</p><p>作者 | 王启隆</p><p>责编 | 唐小引</p><p>出品 | 《新程序员》编辑部</p><p>从 ChatGPT 引发百模大战，GPTs 让人人都能用自然语言构建 GPT，全球范围内对于 AGI 通用人工智能的探索日渐深入，而计算机领域关于“超智能”的神话也愈演愈烈，其中一个广泛传播的观点是，计算机智能最终将超越人类智能，技术奇点即将到来。</p><p>机器智能（图源：AIGC 生成）</p><p>但同时，也有许多科学家对这些热议保持理性或反对的态度。图灵奖得主、中美法三国院士 Joseph Sifakis 认为，再强大的机器也不足以战胜人类的智慧，在他的著作《理解和改变世界》中这样谈道：“我认为科学界应该对这种蒙昧主义和信口开河的混杂产物做出反应，并基于科学和技术标准，对人工智能的前景给出清醒的评估……人们都在热议计算机智能的假想风险，也许把真正的风险掩盖住了，包括引发高失业率、安全性、侵犯隐私权等。”</p><p>Joseph Sifakis，图灵奖得主、中美法三国院士</p><p>Joseph Sifakis 教授出生于 1946 年，是知名的计算机科学家，他的一生都在致力于系统验证和形式化方法在系统设计中的应用，他开发了多个验证工具，提出了解决状态爆炸问题的抽象技术。2007 年，由于在模型检测理论及应用上所做出的杰出贡献，他获得了国际计算机界最高奖——“图灵奖”。</p><p>除了图灵奖得主的身份外，他还是中美法三国院士，对教育充满热忱，与中国渊源深厚，是中国南方科技大学计算机科学与工程系的杰出教授，他说“我对中国学生渴望学习和理解事物的热情印象深刻，我希望能持续看到中国源源不断的创新，因为你们有能力构想并实现一些伟大的事情。”</p><p>怀揣着好奇心与满载的问题，CSDN &《新程序员》首席内容顾问、技术畅销书《编程之美》《构建之法》作者邹欣代表开发者对 Joseph Sifakis 教授（以下简称 Joseph）进行了深度采访，并在 2023 长沙·中国 1024 程序员节的“新程序员全球人工智能高峰论坛”上进行了压轴直播。采访过程中 Sifakis 教授金句频出，展现了他博学而健谈的一面：</p><p>开启电传飞控时代的空客 A320：“四十多年前带领 12 位工程师，用 6 万行 C 语言代码和简单的底层硬件开发了飞机控制系统——这些都很简单。”正文还有更多的技术细节揭露！</p><p>Sifakis 教授近期的研究领域是自动驾驶：“对于关键系统，如自动驾驶汽车，我个人认为最好的解决方案是将神经网络与传统解决方案并行工作。”</p><p>对「奇点时刻」的看法：“完全是胡说八道，是荒谬的。”</p><p>程序员到底该不该在工作中使用 AI：“对于经验丰富的工程师来说，利用 GPT 或其他大模型来提高生产力绝对是正面的。”随后话锋一转：“大模型会毁了初级程序员！”</p><p>AI 的真正风险：“为关键事情做选择的责任从人类转嫁到了机器上。”</p><p>评价计算机科学的未来：“这个时代的计算机科学家应该具备更广泛的文化知识，因为机器正在被应用于不同的领域。”</p><p>在采访中盛赞中国：“你们的创造非常有趣，充满激情和年轻的力量，开拓了我的视野。”</p><p>12 个人、6 万行代码、1 门 C 语言</p><p>开启电传飞控的时代</p><p>再强大的机器也不可能战胜人类的智慧。</p><p>邹欣：首先，请 Joseph 教授向我们的开发者朋友们介绍一下自己，以便大家能够更好地了解您。</p><p>Joseph：我起初在雅典国家技术大学（希腊最古老、最负盛名的大学）学习电子工程，后来出于某种原因我前往了法国学习物理。到了 1970 年，我对物理学的兴趣转移到了计算机课程上，历史上的那一年差不多也是计算机科学的起点。总之，我最终决定放弃物理，转而学习计算机。</p><p>我一生的大部分时间都生活在法国，在那里我创建了自己的实验室，发展了关于系统验证的理论。我们最为人所知的成就包括开发用于空中客车的编程技术、空客 A320（Airbus A320）的嵌入式系统 Ansys SCADE 及其技术认证等。2007 年，我获得了图灵奖，我的一系列工作得到国际的广泛认可。近几年我对自主系统开始感兴趣，尤其是自动驾驶系统。</p><p>邹欣：众所皆知，编程技术具有非常广泛的应用领域，有些仅仅是用于低风险场景，而有些则是用于精细的关键系统，比如导航或支持飞机运行的系统等。但据我所知，要证明一个程序拥有 100% 的准确率是非常困难的，几乎不可能。</p><p>Joseph：没错，为此我们就必须提供一些证实程序准确率的证据，而这正是空中客车面临的挑战，因为空中客车也是世界上第一批使用数字电传操纵飞行控制系统的商用飞机。这个挑战实际上在于说服认证机构，向他们证明，在用计算机取代了所有的电动机械系统后，放一台电脑在飞行员和飞机的机电部件之间，系统就能正常工作。</p><p>事实上，我们不得不为这些系统开发一套编程符号体系以及一个经过认证的编译器。在上世纪 80 年代末 90 年代初，我们真的做了一个编译器出来，并且还应用了一些验证技术。这套系统非常简单，我们只用了不到 6 万行的 C 语言代码就完成了它。</p><p>邹欣：整套系统都是用 C 编写的吗？</p><p>Joseph：我们用的是那种限制重重的 C 语言，没有任何动态特性。那个时候的另一大限制是系统必须在裸机上运行，没有操作系统，所以确保系统的正确性反倒容易得多。因为如果没有任何操作系统，就只需要像编译器一样生成非常简单的循环代码，再设置一个运行时系统来处理外部事件。总而言之，它的原理其实很简单。</p><p>邹欣：这么简单的系统，却完成了一大壮举——据统计，空中客车在 40 年左右的时间里一直以非常安全的记录飞行。</p><p>Joseph：这也是为什么我们在验证上所做的工作已经得到了认可。所谓严格的工程设计技术，意味着要从需求出发，并配备一套严格的方案生成代码，且工程师必须对自己的所有决策作出合理的解释，技术实现也必须具有可行性。实际上，只有空客 A380 采用了真正的操作系统来工作，其他空客都是用我上述提到的方法运行的。</p><p>邹欣：A380 是一个更先进的型号吧？</p><p>Joseph：是的，因为使用操作系统其实会导致更多问题——在我看来，让一个“看似完美的实时操作系统”掌控全局，对于空中客车来说本身就是一大问题。</p><p>邹欣：这样的话题对我这个程序员而言实在很有“杀伤力”，所以请让我稍微深入了解一点技术细节。这个程序可以编译并在裸机上运行，那是否存在一个可以运行的硬件抽象层（HAL），还是直接在设备上进行操作？</p><p>Joseph：没有，取而代之的是一个小调度器，也就是事件管理器。它非常简陋，只有先进先出（FIFO）队列，程序通过将事件放入这个队列，按照一种循环的方式运行。这种循环程序的核心是通过周期性的方式对输入进行采样，继而处理在某个时间段内到达的所有事件。除此之外还涉及了一些技术细节，但整体来说这就是一种非常简单的循环程序，我们称之为响应式编程（Reactive Programming）。</p><p>邹欣：某种意义上，这好像也是一实时系统，对吗？</p><p>Joseph：这是一个硬实时系统，即求在预定的时间内完成任务，没有任何的中断、多任务处理或优先级。因为我们采用了更传统而简洁的方式，让一个事件处理器来满足硬实时系统的基本需求。这个系统使用的循环程序结构就像那艘著名的“五月花号”船一样坚固可靠，事件触发某个动作，满足某个条件即可执行。整个系统就是一个巨大的循环：当条件为真时，执行某个任务；当条件不满足时，执行其他任务；而处理这些任务的方式是一个庞大的分支结构，执行任务，同时每隔一段时间执行一些操作。</p><p>这是一个非常简单的程序，没有动态性也没有指针。原理如此简单，却可以得到一个万分安全的系统，因为它避免了使用多任务处理或优先级处理时可能遇到的所有困难。</p><p>邹欣：非常精彩。这是一个相当巨大的 while（）循环，在循环里还有很多不同的事件。</p><p>Joseph：是的，对于每种情况，确保有足够的时间是很重要的。我们设定了一个固定的周期，时间大约是 10 毫秒左右。这个系统需要确保分析代码、检查每个情况是否能够在规定时间内完成。如果 C 代码足够简单，就可以做到。因此，系统能够提供非常强的响应性保证。唯一的参数就是这个周期，然后你对代码进行分析，针对每种情况进行相应的处理。</p><p>邹欣：这一壮举的关键要素在于，你的程序是机器的唯一掌控者，没有其他因素能干扰到它。</p><p>Joseph：程序员掌控机器，也就掌控了一切的安全问题。</p><p>邹欣：虽然你一直在强调它很简单，但我认为即使从今天的角度来看，这可能仍是世界上最具挑战性且确实可行的系统之一。</p><p>Joseph：说到当年，我们还向那些空中客车的工程师学习，借用了一种叫做同步数据流（Synchronous Data Flow）的建模符号表示法。它就像一个巨大、有输入的数据流网络，是一种类似于模块图示语言的存在。我们就是靠从空客工程师那里学到的同步数据流更精确地定义语义、编写编译技术。</p><p>空客工程师有着电气工程的背景，所以这是他们理解的语言。对于工程师而言，会更熟悉 MATLAB Simulink 这个工具，它实际上更复杂一些。但现在时代不一样了，工程师们只要编写 Simulink 图表，程序就能直接生成 C 代码。</p><p>邹欣：你们大概花了多少人/时间来制作第一个飞行控制系统的版本？</p><p>Joseph：当时，我们为此创建了一个实验室。实验室中有 12 名工程师，原计划用三年来开发程序，但实际上只用了两年来开发第一个版本。实验室的全体工作人员大约有 20 人，但并非所有人都参与了这个项目。其中一些人在我的实验室中开发了一种名为 Lustre 的语言，后来 Esterel Technology 公司接管了这个项目，最终发展为一个叫做 Esterel 的工具，如今仍在使用——总之说来话长，这里面的故事多得说不完。</p><p>邹欣：用编程语言这种抽象的文本形式来控制数十吨的机器起飞和翱翔，真是一件非常浪漫的事情。</p><p>Joseph：在许多行业中，这种思路体现为使用特定领域的语言（DSL）。不必直接在通用编程语言中编写，而是通过 DSL 生成相应代码。这一思想在各个领域都普遍存在，例如 SQL 在数据库领域的应用。使用特定领域语言为系统提供结构化原则，是汽车工业、航空电子和互联网平台等行业的通用做法。通过这种方式，可以有效避免许多潜在问题。</p>', '', 0, '', '2023-11-19 15:35:35', '2024-09-26 19:27:08', 9, 1, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('Rs8QJRZKUxdd079', 10010, 'java', 10001, '后端', '7430015025', 'kkky', '江西省', 'java多线程', '202311/FtP9adZ8wFvxkqu.jpg', '<p>一、什么是多线程 ？</p><p>有了多线程，我们就可以让程序同时做多件事情。</p><p>1. 线程与进程</p><p>线程是操作系统中能够进行运算调度的最小单位。它被包含在进程之中，是进程中的实际运作单位。</p><p>简单理解：应用穿件中相互独立，可以同时运行的功能。</p><p>进程是程序的基本执行实体。</p><p><br></p><p>2. 并发和并行</p><p>并发：在同一时刻，有多个指令在单个CPU上交替执行。</p><p>并行：在同一时刻，有多个指令在多个CPU上同时执行。</p><p> 二、 多线程的实现方式</p><p>继承Thread类的方式进行实现</p><p>实现Runnable接口的方式进行实现</p><p>利用Callable接口和Future接口的方式进行实现</p>', NULL, 0, '有了多线程，我们就可以让程序同时做多件事情。', '2023-11-18 20:29:01', '2024-04-08 19:41:50', 12, 1, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('sxl847ONNg9tAP2', 0, '', 10022, '大学生论坛', '6783480097', 'kkk', '江西省', '测试贴', '202404/8op7k6Odsiplbh7.jpg', '<p>这是一个测试贴</p>', NULL, 0, NULL, '2024-04-03 19:16:27', '2024-04-16 15:18:22', 2, 0, 0, 0, 0, 1);
INSERT INTO `forum_article` VALUES ('X4VPEb3ShoUYAVT', 10016, '蓝桥杯', 10015, '赛事', '3764947030', '80323', '江西省', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', '202404/6IZTg2y8mlVC3g5.jpg', '<h2>🌞1.蓝桥杯到底是什么?</h2><p> &nbsp; &nbsp; &nbsp; &nbsp;蓝桥杯全国软件和信息技术专业人才大赛，是由工业和信息化部人才交流中心举办的全国性IT学科赛事。全国1200余所高校参赛，累计参赛人数超过40万人。蓝桥杯大赛连续两年被列入中国高等教育学会发布的“全国普通高校学科竞赛排行榜”，是高校教育教学改革和创新人才培养的重要竞赛项目。对大学生综合评测，奖学金评定，升学考研都有一定助益。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;蓝桥杯大赛共包括三个竞赛组别，个人赛-软件类，个人赛-电子类，以及视觉艺术大赛。其中个人赛-软件类的比赛科目包括C/C++程序设计、Java软件开发、Python程序设计。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;附上蓝桥杯官网地址：蓝桥杯官网（个人报名通道即将开启，看完这篇文章赶快去报名吧）</p><h2> 🌞2.我们为什么要参加蓝桥杯?</h2><h3> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;🍋1.含金量高，被绝大多数高校和企业认可</h3><p> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;其实从上面蓝桥杯的简介我们就能看出来，蓝桥杯在我国高校中的it比赛中的知名度非常高，即使是清华北大和顶尖985的高校学子参加的人也是络绎不绝。只要你获得好成绩，甚至能当场获得一些大厂的青睐，如像百度、方正等大公司。 即使你没有获得非常优秀的成绩，它同样对你的大学生综合评测，奖学金评定，升学考研都有一定助益。可以说是作为it大学生不可或缺的一项比赛</p><h3> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;🍋2. 分组比赛，防止被\"屠杀\"</h3><p> &nbsp; &nbsp; &nbsp; &nbsp;这是蓝桥杯最有特色也是它最贴心的地方，蓝桥杯的赛道分为研究生组、大学A组、大学B组、大学C组。研究生组说明是研究生的组别，研究生只能参加这个。大学A组是重点本科参加的组别，包括所有985、211的学校。大学B组是普通本科院校，也是参赛人数几乎最多的赛道，大学C组是高职高专组。高组别的不能报考低组别的，但是低组别可以越级报考高组别，比如你是普通本科你也可以报考大学A组（只要你有自信）</p><p> &nbsp; &nbsp; &nbsp; &nbsp;这样的分组有什么好处呢？它将实力相近的人群放到一个组别，防止参赛选手实力差距过大，导致奖项全被更好的学校包揽。为每一个高校学子都提供了一个更加公平的竞技平台。举个例子：一个B组或C组的参加比赛，发现遇到的都是顶尖985的ACM职业比赛选手来降维打击，那不是被吃的渣都不剩。这样低组别的话学生谁还会想报名呢？ </p><h3> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;🍋3.参赛门槛低，获奖容易</h3><p> &nbsp; &nbsp; &nbsp; &nbsp;这一点通过上面大家都可以感受得到，蓝桥杯是所有的高校学子都有参加的机会。而且即使你不以院校的名义参加，现在也可以以个人的名义参加比赛，只需要缴纳报名费三百元即可。有的人一听到这，三百？这么多。别担心，蓝桥杯的比赛基本上只要你肯认真去学习准备，拿个最低的省三等奖是非常容易的，而大部分的院校只要你能拿奖，是都可以报销的。当然你要说你光报名不去准备那肯定这三百块是去交智商税了。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;接下来说说蓝桥杯的获奖机制：蓝桥杯分为省赛和国赛。省赛排名的前百分之10获得省一等奖，接下来的百分之20为省二等奖，再下来的百分之30省三等奖。可以说，只要你的排名在前60%你就可以获奖，你就可以报销报名费了。如果你有幸拿了省一等奖，还可以参加国赛，进入国赛后即使你最差也可以拿到一个国家三等奖。可以说蓝桥杯这样的获奖机制，即使是大一大二的学习参加，获奖也是非常容易的。即使大一大二未取得很好的成绩，可有了这次比赛经验，大三大四再去参加就已经比其他选手有着不小的优势了 </p><h3> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;🍋4.公司对算法的能力要求越来越高</h3><p> &nbsp; &nbsp; &nbsp; &nbsp; 现在整个it行业的公司无论是大厂还是小厂，无论是校招还是社招，对算法的考察都是必须的。对于大厂来说，你的算法不过关，不好意思我们不要你。对于小厂来说，你的算法不过关，对不起我们不能给你更高的职位和薪资。所以在我们准备蓝桥杯的过程学习算法的过程，同时也是为了我们未来就业做准备。可以说，算法能力决定了你的钱途和前途。想要在未来拿个好offer，参加蓝桥杯正是你不可或缺的。</p><h2> 🌞3.现在0基础参加还来得及吗?</h2><p> &nbsp; &nbsp; &nbsp; &nbsp;现在参加一点都不晚。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;蓝桥杯现在只是处在报名阶段，它真正比赛的日期要在明年四月份左右。不严格意义的来算，你甚至还有半年的时间去学习和准备。任何事情能够坚持半年，都能为一个人带来巨大的蜕变。只要你每周能拿出一点时间学习算法，持之以恒，正所谓士别三日还将刮目想看，半年的学习，完全能让你成功成为一个算法小将，甚至更加优秀。下面我也会为大家推荐合适的学习方法和路线</p><h2> 🌞4.蓝桥杯考的是什么?难吗？和ACM有什么区别？</h2><p> &nbsp; &nbsp; &nbsp; &nbsp; 蓝桥杯的省赛有十道题，四个钟的时间。其中题目报考填空题和编程题，填空题只要你的答案正确即可得分，编程题即使你的答案不对，也可以按步骤得分，可以说非常的人性化。它不同于ACM的ACM团队赛制，ACM题目是英语的，必须运行的结果正确才可得分。ACM的题目要更加难，考差的更多是人的思维能力，也可以说是天赋，它并不适合大部分人去参加，而且需要付出的时间也更多。而蓝桥杯的题目虽然称不上是非常难，但也并非人人都能会的。但你如果肯花一些时间去学习，那它给你的结果也肯定不会让你失望。它的题型比较单一，更多的是考差学习掌握了哪些算法能力。蓝桥杯的题型更喜欢考暴力、枚举、动规等问题。</p><h2> 🌞5.备战蓝桥的学习路线和刷题网站</h2><p> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 如果你是C/C++的选手，那我劝你一定要认真学好所有的基础算法。C和C++都是非常适合用来写算法的语言，所以这个组别的选手大多都是有一定的实力的，如果你想来混可能被吃的渣都不剩。当然其他两组选手也非常多，所以也需要认真去复习，先看看我归纳的学习路线图</p><p> &nbsp; &nbsp; &nbsp; &nbsp;不要一下觉得很多，很多都是在学校的课程中学到过的，而且你还有半年的时间，想要掌握这里面的大部分算法完全时间绰绰有余。当然也为大家推荐了一些好的学习算法和数据结构的网站。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;首先必须推荐的肯定是蓝桥杯真题的官方指定OJ——蓝桥云课。参加蓝桥杯的话一定得来这上面刷题——题库 - 蓝桥云课。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;力扣（yyds）：力扣刷题网 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; </p><p> &nbsp; &nbsp; &nbsp; &nbsp;牛客网（同样经典的刷题网站）：牛客刷题网</p><p> &nbsp; &nbsp; &nbsp; &nbsp;PTA（适合小白）：PTA平台</p><p> &nbsp; &nbsp; &nbsp; VisuAlgo 数据结构和算法动态可视化（学习数据结构的神器）：VisuAlgo - 数据结构和算法动态可视化 (Chinese) &nbsp;</p><p> &nbsp; &nbsp; &nbsp; 当然别忘记了哔哩哔哩大学，里面也有非常优秀的资源，下面向大家推荐几个我自己学习过的：图灵数据结构与算法：这可能是B站讲的最好的数据结构算法-leetcode真题解析（2021年最新版）_哔哩哔哩_bilibili</p><p> &nbsp; &nbsp; &nbsp; &nbsp;我认为最好的Java数据结构教程:黑马程序员Java数据结构与java算法，全网资料最全数据结构+算法教程，154张java数据结构图_哔哩哔哩_bilibili</p><p> &nbsp; &nbsp; &nbsp; &nbsp;上面两个视频别忘记了获取配套的学习资源，其中下面黑马的数据结构的配套的PDF我认为做的非常的好</p><p> &nbsp; &nbsp; &nbsp; &nbsp;当然别忘记关C站最强算法大佬：英雄哪里出来:英雄的博客链接 </p><p>大佬的文章讲解了各种从易到难的算法，而且讲的非常透彻，有什么不懂得也可以去加入他的群聊，和更多优秀的人一起学习算法。大佬最近也在带领萌新们一起刷题，想学习的更快更好，一定要去了解一下</p><h2> 🌞6.如何正确的刷题？</h2><p> &nbsp; &nbsp; &nbsp; &nbsp; 这里我结合自身刷题的经验和一些博主的推荐向大家推荐一下，如果你是零基础或者基础不好的，每次只是闲着无聊才坐一两题，现在想系统的学习算法。我推荐你先去力扣网站</p><p> &nbsp; &nbsp; &nbsp; &nbsp;在这选择难度简单，然后挑一些题解量高，通过率过的题目试试水。这类题目基本比较简单，不会涉及到什么算法，每次提交成功都可以激发你学习算法的兴趣。即使做不出来里面也有许多大佬的题解五花八门，让你们一眼看懂他们的神奇思路。有的人总是好高骛远，入门就去学什么贪心动态，一道题看两三个钟头，结果最后题解都看不懂，这是学习算法的大忌。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;等你试水完毕有了一定做题经验后，我推荐你去参加力扣的学习计划专栏，这些都是免费的，从双指针到动规和数据结构都有，可以帮你一步一步帮你训练出优秀的算法能力。</p><p> &nbsp; &nbsp; &nbsp; &nbsp;刷题也千万不要忘记归纳总结！！！ &nbsp; &nbsp; &nbsp; &nbsp;</p><p> &nbsp; &nbsp; &nbsp; &nbsp;刷题并不是刷完就过了即可，题目在变化，但题型永远就那么一些。只有归纳出属于自己的一套笔记，才能做题越来越得心应手。将考点相同的算法点总结，再去寻找类似的算法题看能否做出来检验自己，这样才能搞明白自己是否真的学会了这个算法。 &nbsp; &nbsp; </p><p> &nbsp; &nbsp; &nbsp; &nbsp;我为大家推荐的是我自己常用的笔记软件语雀，贴上部分我做的笔记，可以直接贴图非常方便。当然还有有道云笔记，Typora等等都非常不错</p><h2> &nbsp;🌞7.蓝桥年真题资源+配套考试环境</h2><p>链接：https://pan.baidu.com/s/1AqH5kQVZ5bFGptlUm8zyvw </p><p>提取码：EDG6 </p><p>--来自百度网盘超级会员V3的分享</p>', '', 0, '', '2023-11-19 15:47:21', '2024-11-11 04:05:57', 166, 3, 3, 0, 1, 1);
INSERT INTO `forum_article` VALUES ('yIyTsgFIvNrPMfs', 0, '', 10001, '后端', '3764947030', '80323', '江西省', '55555555', '202311/BtofukHj9MROL6w.png', '<p data-v-md-line=\"1\">6666666666666</p>\r\n', '6666666666666', 1, NULL, '2023-11-25 00:44:06', '2024-04-03 18:45:13', 0, 0, 0, 0, 1, -1);
INSERT INTO `forum_article` VALUES ('ylOlffcmY8BWjj8', 10027, '英语四六级', 10022, '大学生论坛', '3764947030', '80323', '江西省', '英语四级比计算机等级难多少,英语四级难考吗？学长：掌握方法，过“425”分不困难...', '202404/bNQGG36FIGMA2BO.jpg', '<p style=\"text-align: start;\">随着时间的推移，下半年大学英语四六级考试的时间，在日趋临近；对于备战这场考试的大学生来说，可供大家复习的时间，也在日益减少。</p><p style=\"text-align: start;\">整个大学几年里，英语和计算机考试，是每一个本科生，不可避开的话题。</p><p style=\"text-align: start;\">一些高校，为了督促大学生们，用心学习英语，提升英语四级的通过率，甚至将CET-4是否合格，与能否拿到学位证书、毕业证书相挂钩。</p><p style=\"text-align: start;\">在笔者读书生涯中，就有一位舍友，从大一到大四，一直未能通过英语四级考试，大学毕业的时候，成为班级里，唯一一个未拿到学位证的同学，想一想，还是挺遗憾的。</p><p style=\"text-align: center;\"><img src=\"/api/file/getImage/202311/7miD3vH54tBJX3Dxp4LFEHtN96FqLG.jpg\" alt=\"\" data-href=\"\" style=\"\"></p><p style=\"text-align: start;\">许多学生，从大一开始，就为了通过英语四级这一目标而努力，直到大学毕业前，才勉强通过。</p><p style=\"text-align: start;\">要知道，对于大学生来说，更应该专注于专业课的学习，除了英语专业的大学生，英语这门科目，应该是一门辅助性的功课。</p><p style=\"text-align: start;\">如果花费太多的精力与时间，仅仅是为了通过一场考试，就显得过犹不及了。所以，高效地备战英语四级，争取在大学期间，有更多的自由时间，才是一种明智的选择。</p><p style=\"text-align: start;\">想要在英语四级考试中，达到合格分数线，真得很难吗？我们一起来看看吧。</p><p style=\"text-align: center;\"><br></p><p style=\"text-align: start;\">为了让英语四、六级，获得更多的认可度，改革之后的英语四级，从难度上来看有所提升。</p><p style=\"text-align: start;\">全国大学英语四级考试，总成绩为710分，听力与阅读理解部分，占据较大的分值，同时兼顾学生英语写作能力、翻译能力的培养。</p><p style=\"text-align: start;\">虽然说，这场考试已经不舍及格的分数线，但是却规定了425分及以上，可以继续报考六级，一般默认425分为合格线。</p><p style=\"text-align: start;\">当然，在英语四级考试中，考出的分数越多越好，英语四级证书上的得分，不仅代表着你在英语方面的掌握程度，对将来的求职找工作，也会大有益处。</p><p style=\"text-align: start;\">那么，作为一名大学生，应该怎样备考英语四级，才能轻松过关呢？学长建议，掌握方法，过“425”分不困难。</p><p style=\"text-align: center;\"><br></p><p style=\"text-align: start;\">丰富词汇量</p><p style=\"text-align: start;\">作为一门语言科目，若想学好英语，首先要有一定的词汇基础。无论是听力、阅读理解、作文，还是翻译，都离不开词汇量的掌握。</p><p style=\"text-align: start;\">在备战英语四级之前，大学校园里，时常能看到这样的场景，学生人手一本英语单词手册，希望借此来丰富自己的词汇量。</p><p style=\"text-align: start;\">其实，依靠自己的记忆力，单纯的去积累单词，并不是一种好方法。如果能通过句子，将词汇放入语境中去理解和掌握，会帮助大家，更好地掌握词汇，也能培养同学们的语感。</p><p style=\"text-align: start;\">将一个个生僻的词汇，单独进行记忆，不如将许多相似的词汇，进行对比记忆，这样的结果，不仅能加深记忆，也能避开词汇混淆。</p><p style=\"text-align: start;\">找一本合适的词汇手册，将许多的近义词、同义词或者反义词，进行归纳总结，大家只需要划出重点，反复记忆，通常能轻松增加个人的词汇量。</p><p style=\"text-align: center;\"><br></p><p style=\"text-align: start;\">提升知识面</p><p style=\"text-align: start;\">无论理解题意，还是做阅读理解部分，都需要同学们，具备良好的理解能力。</p><p style=\"text-align: start;\">如果想在考试中，取得优异的成绩，阅读理解这部分的分值，是大家不可忽略的；提升我们的知识面，将会在英语考试的时候，思如泉涌、轻松应对。</p><p style=\"text-align: start;\">在英语四级考试之前，提升阅读理解能力，不仅仅限于对内容的理解，还需要提升大家阅读的速度，要知道，英语考试过程中，对解题的速度也有一定的要求。</p><p style=\"text-align: start;\">阅读理解的内容，时常涉及宽泛，这就需要我们在备考的过程中，有意识地丰富英语知识的储备，甚至了解国外的一些风土人情。</p><p style=\"text-align: start;\">除了阅读教材之外，同学们还可以通过影视节目，来提高我们的阅读理解能力。在轻松的环境中，掌握一些俗语，也能帮助我们提升听力，加深单词的记忆等。</p><p style=\"text-align: center;\"><br></p><p style=\"text-align: start;\">多背诵文章</p><p style=\"text-align: start;\">英语的学习，离不开听说读写能力的培养，其中，背诵文章，可以让大家提升英语方面的综合素养，让同学们受益匪浅。</p><p style=\"text-align: start;\">大量的阅读，可以丰富大家的知识面，但是大量的背诵文章，却可以提升我们的语感，在解题的过程中，变得游刃有余。</p><p style=\"text-align: start;\">比如说，若想在听力环节，取得满意的成绩，离不开大家耳朵对听力内容的捕捉能力；而在大声背诵英语文章的过程中，能够有效提升大家对英语词汇的敏锐度。</p><p style=\"text-align: start;\">在写作的过程中，时常考验着，大家在英语方面的综合素养。如果同学们缺乏基础，想要考出高分，将会很难。</p><p style=\"text-align: start;\">不过，我们却可以通过背诵范文，来争取更多的分数。多背诵英语范文，注意写作模板，并且在考试的过程中，将字迹写工整，都将有效提升我们的分数。</p><p style=\"text-align: center;\"><br></p><p style=\"text-align: start;\">虽然说，在大学几年里，想要通过英语四级考试，同学们会有许多次考试的机会，但是大家要知道，如果将大部分的精力和时间，花费在这场考试上，将会影响同学们的心情，还会占据大量的学习时间。</p><p style=\"text-align: start;\">同学们不妨在考试到来之前，掌握英语学习的技巧，争取一次性通过考试。不要抱着，这次考不过，下次再争取的念头，这样下去，只会让自己变得越来越焦虑。</p>', '', 0, '', '2023-11-19 15:41:42', '2024-09-23 13:23:27', 29, 2, 2, 0, 0, 1);

-- ----------------------------
-- Table structure for forum_article_attachment
-- ----------------------------
DROP TABLE IF EXISTS `forum_article_attachment`;
CREATE TABLE `forum_article_attachment`  (
  `file_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文件ID',
  `article_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文章ID',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '用户id',
  `file_size` bigint(20) NULL DEFAULT NULL COMMENT '文件大小',
  `file_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '文件名称',
  `download_count` int(11) NULL DEFAULT NULL COMMENT '下载次数',
  `file_path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '文件路径',
  `file_type` tinyint(4) NULL DEFAULT NULL COMMENT '文件类型',
  `integral` int(11) NULL DEFAULT NULL COMMENT '下载所需积分',
  PRIMARY KEY (`file_id`) USING BTREE,
  INDEX `idx_article_id`(`article_id`) USING BTREE,
  INDEX `idx_user_id`(`user_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '文件信息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of forum_article_attachment
-- ----------------------------
INSERT INTO `forum_article_attachment` VALUES ('014569155409431', 'RtiXj832TFL4nhW', '1890524956', 425672, '帅照.zip', 2, '202301/TADTC77LNjeO7Bs.zip', 0, 0);
INSERT INTO `forum_article_attachment` VALUES ('092253322359480', '0XHRpvcW13aTVMu', '6783480097', 105950, '1.zip', 4, '202404/sJXtvL8oawJBTjf.zip', 0, 3);
INSERT INTO `forum_article_attachment` VALUES ('137556953382601', 'yIyTsgFIvNrPMfs', '3764947030', 105950, '1.zip', 0, '202311/tIEFuIY1Yv5KDcO.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('141600281551986', 'CPWUe9ujqFHjthh', '7430015025', 21668, 'homeWork.zip', 3, '202311/wThoCgr2BuWeURn.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('199131163992654', 'Uke2ni3RKgA4C0p', '6783480097', 105950, '1.zip', 0, '202311/ukux3aG6QAiX3pn.zip', 0, 2);
INSERT INTO `forum_article_attachment` VALUES ('353610950040024', 'w11fkdcrx8iykIq', '6783480097', 105950, '1.zip', 0, '202311/UmZMnywu9IQmLTH.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('461805804564684', 'bEEIzLEU5STfoRt', '6783480097', 105950, '1.zip', 0, '202311/tnazpRdcWpYQDId.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('515672539523839', 'qb1oWQ94GQBdyZG', '6783480097', 105950, '1.zip', 0, '202311/a1vYQnxuaRYDmLz.zip', 0, 0);
INSERT INTO `forum_article_attachment` VALUES ('628401493302272', 'X4VPEb3ShoUYAVT', '3764947030', 105950, '1.zip', 2, '202311/aqdMww8fse11dkN.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('670985347930723', 'aYa8yjvk4fxMbYM', '6783480097', 105950, '1.zip', 0, '202311/gMh42V4hpxrfNFz.zip', 0, 0);
INSERT INTO `forum_article_attachment` VALUES ('678496798437905', 'MCXueWkxxZBTgih', '6783480097', 105950, '1.zip', 0, '202311/sUmvfbvMEyverwO.zip', 0, 5);
INSERT INTO `forum_article_attachment` VALUES ('923938159995280', 'Nluq0qAze4xmRBg', '3764947030', 105950, '1.zip', 0, '202311/74YkKlpxrd2mMy6.zip', 0, 5);

-- ----------------------------
-- Table structure for forum_article_attachment_download
-- ----------------------------
DROP TABLE IF EXISTS `forum_article_attachment_download`;
CREATE TABLE `forum_article_attachment_download`  (
  `file_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文件ID',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户id',
  `article_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文章ID',
  `download_count` int(11) NULL DEFAULT 1 COMMENT '文件下载次数',
  PRIMARY KEY (`file_id`, `user_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户附件下载' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of forum_article_attachment_download
-- ----------------------------
INSERT INTO `forum_article_attachment_download` VALUES ('014569155409431', '6783480097', 'RtiXj832TFL4nhW', 2);
INSERT INTO `forum_article_attachment_download` VALUES ('092253322359480', '3159491214', '0XHRpvcW13aTVMu', 1);
INSERT INTO `forum_article_attachment_download` VALUES ('092253322359480', '6783480097', '0XHRpvcW13aTVMu', 3);
INSERT INTO `forum_article_attachment_download` VALUES ('141600281551986', '6783480097', 'CPWUe9ujqFHjthh', 2);
INSERT INTO `forum_article_attachment_download` VALUES ('141600281551986', '7430015025', 'CPWUe9ujqFHjthh', 1);
INSERT INTO `forum_article_attachment_download` VALUES ('628401493302272', '6783480097', 'X4VPEb3ShoUYAVT', 1);
INSERT INTO `forum_article_attachment_download` VALUES ('628401493302272', '7183809612', 'X4VPEb3ShoUYAVT', 1);

-- ----------------------------
-- Table structure for forum_board
-- ----------------------------
DROP TABLE IF EXISTS `forum_board`;
CREATE TABLE `forum_board`  (
  `board_id` int(11) NOT NULL AUTO_INCREMENT COMMENT '板块ID',
  `p_board_id` int(11) NULL DEFAULT NULL COMMENT '父级板块ID',
  `board_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '板块名',
  `cover` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '封面',
  `board_desc` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '描述',
  `sort` int(11) NULL DEFAULT NULL COMMENT '排序',
  `post_type` tinyint(1) NULL DEFAULT 1 COMMENT '0:只允许管理员发帖 1:任何人可以发帖',
  PRIMARY KEY (`board_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10029 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '文章板块信息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of forum_board
-- ----------------------------
INSERT INTO `forum_board` VALUES (10000, 0, '前端', NULL, '前端', 3, 1);
INSERT INTO `forum_board` VALUES (10001, 0, '后端', NULL, '后端', 1, 1);
INSERT INTO `forum_board` VALUES (10003, 10000, 'Vue', NULL, 'Vue', 1, 1);
INSERT INTO `forum_board` VALUES (10004, 10000, 'React', NULL, 'React', 2, 1);
INSERT INTO `forum_board` VALUES (10006, 0, '乐园管理', NULL, '该模块只能由管理员发贴，主要发布一些平台公告', 9, 0);
INSERT INTO `forum_board` VALUES (10007, 10006, '规章制度', NULL, '规章制度', 1, 0);
INSERT INTO `forum_board` VALUES (10009, 0, '人工智能', NULL, NULL, 2, 1);
INSERT INTO `forum_board` VALUES (10010, 10001, 'java', NULL, NULL, 2, 1);
INSERT INTO `forum_board` VALUES (10011, 0, '数据结构', NULL, '666', 4, 1);
INSERT INTO `forum_board` VALUES (10012, 0, 'python', NULL, NULL, 6, 1);
INSERT INTO `forum_board` VALUES (10015, 0, '赛事', NULL, '', 7, 1);
INSERT INTO `forum_board` VALUES (10016, 10015, '蓝桥杯', NULL, NULL, 1, 1);
INSERT INTO `forum_board` VALUES (10017, 10015, 'icpc', NULL, NULL, 2, 1);
INSERT INTO `forum_board` VALUES (10018, 10015, '科技月月评', NULL, NULL, 3, 1);
INSERT INTO `forum_board` VALUES (10019, 10015, '软件创新设计大赛', NULL, NULL, 4, 1);
INSERT INTO `forum_board` VALUES (10020, 10009, 'openAI', NULL, NULL, 1, 1);
INSERT INTO `forum_board` VALUES (10021, 10009, 'openCV', NULL, NULL, 2, 1);
INSERT INTO `forum_board` VALUES (10022, 0, '大学生论坛', '202404/ibvMVekUN71IImO.jpg', '', 5, 1);
INSERT INTO `forum_board` VALUES (10023, 10022, '高数', NULL, NULL, 1, 1);
INSERT INTO `forum_board` VALUES (10024, 10022, '线代', NULL, NULL, 2, 1);
INSERT INTO `forum_board` VALUES (10025, 10022, 'c语言', NULL, NULL, 3, 1);
INSERT INTO `forum_board` VALUES (10026, 10022, '大学英语', NULL, NULL, 4, 1);
INSERT INTO `forum_board` VALUES (10027, 10022, '英语四六级', NULL, NULL, 5, 1);
INSERT INTO `forum_board` VALUES (10028, 0, '知享社区', '202311/m0fEMAzXbtKhpKM.jpg', '大家可以在这里畅所欲言，分享你的一切', 8, 1);

-- ----------------------------
-- Table structure for forum_comment
-- ----------------------------
DROP TABLE IF EXISTS `forum_comment`;
CREATE TABLE `forum_comment`  (
  `comment_id` int(11) NOT NULL AUTO_INCREMENT COMMENT '评论ID',
  `p_comment_id` int(11) NULL DEFAULT NULL COMMENT '父级评论ID',
  `article_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '文章ID',
  `content` varchar(800) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '回复内容',
  `img_path` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '图片',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户ID',
  `nick_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '昵称',
  `user_ip_address` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '用户ip地址',
  `reply_user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '回复人ID',
  `reply_nick_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '回复人昵称',
  `top_type` tinyint(4) NULL DEFAULT 0 COMMENT '0:未置顶  1:置顶',
  `post_time` datetime NULL DEFAULT NULL COMMENT '发布时间',
  `good_count` int(11) NULL DEFAULT 0 COMMENT 'good数量',
  `status` tinyint(4) NULL DEFAULT NULL COMMENT '0:待审核  1:已审核',
  PRIMARY KEY (`comment_id`) USING BTREE,
  INDEX `idx_article_id`(`article_id`) USING BTREE,
  INDEX `idx_post_time`(`post_time`) USING BTREE,
  INDEX `idx_top`(`top_type`) USING BTREE,
  INDEX `idx_p_id`(`p_comment_id`) USING BTREE,
  INDEX `idx_status`(`status`) USING BTREE,
  INDEX `idx_user_id`(`user_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10056 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '评论' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of forum_comment
-- ----------------------------
INSERT INTO `forum_comment` VALUES (10004, 10000, 'RtiXj832TFL4nhW', '6666666', NULL, '6783480097', 'kkk', '江西省', '1890524956', '测试账号', 0, '2023-11-07 21:56:53', 1, 1);
INSERT INTO `forum_comment` VALUES (10005, 10000, 'RtiXj832TFL4nhW', 'hhhhhh', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-07 21:59:22', 1, 1);
INSERT INTO `forum_comment` VALUES (10006, 0, 'fj8Fm1KHg8vWywx', '666kkk', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-07 22:36:48', 0, 1);
INSERT INTO `forum_comment` VALUES (10007, 0, 'fj8Fm1KHg8vWywx', 'nb\r<br>\r<br>', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-08 20:57:25', 1, 1);
INSERT INTO `forum_comment` VALUES (10008, 10000, 'RtiXj832TFL4nhW', '触发后续的发挥', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-08 23:10:19', 1, 1);
INSERT INTO `forum_comment` VALUES (10009, 10007, 'fj8Fm1KHg8vWywx', '哎呦你干嘛', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-15 21:54:13', 0, 1);
INSERT INTO `forum_comment` VALUES (10010, 0, 'fj8Fm1KHg8vWywx', '66666', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-15 22:46:50', 0, 1);
INSERT INTO `forum_comment` VALUES (10011, 0, 'fj8Fm1KHg8vWywx', '555555\r<br>', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-15 22:49:54', 1, 1);
INSERT INTO `forum_comment` VALUES (10012, 10011, 'fj8Fm1KHg8vWywx', '1111616', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-15 22:50:06', 0, 1);
INSERT INTO `forum_comment` VALUES (10013, 10011, 'fj8Fm1KHg8vWywx', '111', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-15 22:50:10', 0, 1);
INSERT INTO `forum_comment` VALUES (10014, 0, '0XHRpvcW13aTVMu', '太棒了555', NULL, '7430015025', 'kkky', '江西省', '', NULL, 0, '2023-11-18 19:53:16', 3, 1);
INSERT INTO `forum_comment` VALUES (10015, 0, '0XHRpvcW13aTVMu', '学废了学废了', NULL, '7430015025', 'kkky', '江西省', '', NULL, 0, '2023-11-18 20:22:55', 0, 1);
INSERT INTO `forum_comment` VALUES (10016, 0, 'CPWUe9ujqFHjthh', '记得点赞哦', NULL, '7430015025', 'kkky', '江西省', '', NULL, 0, '2023-11-18 20:23:12', 1, 1);
INSERT INTO `forum_comment` VALUES (10017, 10016, 'CPWUe9ujqFHjthh', '哎哟你干嘛', NULL, '6783480097', 'kkk', '江西省', '7430015025', 'kkky', 0, '2023-11-18 20:25:03', 0, 1);
INSERT INTO `forum_comment` VALUES (10018, 0, 'ylOlffcmY8BWjj8', '666', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2023-11-19 15:41:54', 1, 1);
INSERT INTO `forum_comment` VALUES (10019, 0, '0XHRpvcW13aTVMu', '测试评论', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-19 17:49:31', 0, 1);
INSERT INTO `forum_comment` VALUES (10020, 10014, '0XHRpvcW13aTVMu', '哈哈哈', NULL, '6783480097', 'kkk', '江西省', '7430015025', 'kkky', 0, '2023-11-19 17:49:39', 1, 1);
INSERT INTO `forum_comment` VALUES (10021, 10014, '0XHRpvcW13aTVMu', '记得三连', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-19 17:49:55', 2, 1);
INSERT INTO `forum_comment` VALUES (10022, 0, 'ylOlffcmY8BWjj8', '可以可以', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-19 17:53:10', 0, 1);
INSERT INTO `forum_comment` VALUES (10023, 10018, 'ylOlffcmY8BWjj8', '哎哟你干嘛', NULL, '6783480097', 'kkk', '江西省', '3764947030', '80323', 0, '2023-11-19 17:53:22', 1, 1);
INSERT INTO `forum_comment` VALUES (10024, 0, '0XHRpvcW13aTVMu', '这是一个图片评论', '202311/l8gLcPDlEB1WJ2j.jpg', '7430015025', 'kkky', '江西省', '', NULL, 0, '2023-11-19 21:38:42', 1, 1);
INSERT INTO `forum_comment` VALUES (10025, 0, 'CPWUe9ujqFHjthh', '不好看', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2023-11-19 22:33:03', 0, -1);
INSERT INTO `forum_comment` VALUES (10026, 0, 'AXY6tGgAKwOUBEn', '躺着学', NULL, '3159491214', '念', '江西省', '', NULL, 0, '2023-11-21 19:16:37', 1, 1);
INSERT INTO `forum_comment` VALUES (10027, 0, '0XHRpvcW13aTVMu', '666', '202311/tNo2RdbhV3teHKE.jpg', '3159491214', '念', '江西省', '', NULL, 0, '2023-11-21 19:24:16', 0, 1);
INSERT INTO `forum_comment` VALUES (10028, 10014, '0XHRpvcW13aTVMu', '666', NULL, '3159491214', '念', '江西省', '6783480097', 'kkk', 0, '2023-11-21 19:24:26', 0, -1);
INSERT INTO `forum_comment` VALUES (10029, 0, '0XHRpvcW13aTVMu', '666', NULL, '3159491214', '念', '江西省', '', NULL, 0, '2023-11-21 21:16:44', 0, 1);
INSERT INTO `forum_comment` VALUES (10030, 0, '0XHRpvcW13aTVMu', '666', '202311/CxTrNQAQaWYu8sz.jpg', '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-21 21:20:14', 1, 1);
INSERT INTO `forum_comment` VALUES (10031, 10015, '0XHRpvcW13aTVMu', 'hhh<br>', NULL, '6783480097', 'kkk', '江西省', '7430015025', 'kkky', 0, '2023-11-21 21:20:29', 0, 1);
INSERT INTO `forum_comment` VALUES (10032, 0, '0XHRpvcW13aTVMu', '6666666666666666666666666', '202311/oIqJdRWWzbATnGh.jpg', '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-21 21:29:41', 1, 1);
INSERT INTO `forum_comment` VALUES (10033, 10024, '0XHRpvcW13aTVMu', '666', NULL, '6783480097', 'kkk', '江西省', '7430015025', 'kkky', 0, '2023-11-21 21:29:52', 0, -1);
INSERT INTO `forum_comment` VALUES (10034, 0, '0XHRpvcW13aTVMu', 'hhh', NULL, '3159491214', '念', '江西省', '', NULL, 0, '2023-11-21 21:40:56', 1, 1);
INSERT INTO `forum_comment` VALUES (10035, 0, '0XHRpvcW13aTVMu', '5555555555555', '202311/6eSk12ktwhKcWEG.jpg', '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-21 21:46:28', 1, 1);
INSERT INTO `forum_comment` VALUES (10036, 10024, '0XHRpvcW13aTVMu', 'hhhh', NULL, '6783480097', 'kkk', '江西省', '7430015025', 'kkky', 0, '2023-11-21 21:46:33', 0, 1);
INSERT INTO `forum_comment` VALUES (10037, 10024, '0XHRpvcW13aTVMu', 'hhh', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2023-11-21 21:46:36', 0, -1);
INSERT INTO `forum_comment` VALUES (10038, 0, 'AXY6tGgAKwOUBEn', 'hhh', '202311/z05IVDOtFimaF8W.jpg', '6783480097', 'kkk', '江西省', '', NULL, 0, '2023-11-21 22:40:14', 0, 1);
INSERT INTO `forum_comment` VALUES (10039, 0, '0XHRpvcW13aTVMu', '666', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2023-11-25 00:41:49', 0, 1);
INSERT INTO `forum_comment` VALUES (10040, 0, '0XHRpvcW13aTVMu', '666', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2023-11-25 00:43:03', 0, -1);
INSERT INTO `forum_comment` VALUES (10041, 10019, '0XHRpvcW13aTVMu', '5555', NULL, '6783480097', 'kkk', '江西省', '6783480097', 'kkk', 0, '2024-03-10 14:22:55', 0, 1);
INSERT INTO `forum_comment` VALUES (10042, 10027, '0XHRpvcW13aTVMu', 'hhhh', NULL, '6783480097', 'kkk', '未知', '3159491214', '念', 0, '2024-03-11 15:52:48', 0, 1);
INSERT INTO `forum_comment` VALUES (10043, 0, 'bEEIzLEU5STfoRt', '哈哈哈哈哈', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2024-04-03 19:05:38', 0, 1);
INSERT INTO `forum_comment` VALUES (10044, 0, 'CPWUe9ujqFHjthh', '测试测试测', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2024-04-03 19:07:28', 1, 1);
INSERT INTO `forum_comment` VALUES (10045, 10044, 'CPWUe9ujqFHjthh', '哈哈哈', NULL, '7430015025', 'kkky', '江西省', '6783480097', 'kkk', 0, '2024-04-08 19:43:23', 0, 1);
INSERT INTO `forum_comment` VALUES (10046, 10016, 'CPWUe9ujqFHjthh', '你干嘛', NULL, '7430015025', 'kkky', '江西省', '6783480097', 'kkk', 0, '2024-04-08 19:43:29', 0, 1);
INSERT INTO `forum_comment` VALUES (10047, 0, 'X4VPEb3ShoUYAVT', '哈哈哈哈', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2024-04-16 11:21:56', 1, 1);
INSERT INTO `forum_comment` VALUES (10048, 0, 'X4VPEb3ShoUYAVT', '狗都不学算法', NULL, '3764947030', '80323', '江西省', '', NULL, 0, '2024-04-16 11:22:14', 1, 1);
INSERT INTO `forum_comment` VALUES (10049, 10048, 'X4VPEb3ShoUYAVT', '我还是走开发吧', NULL, '3764947030', '80323', '江西省', '3764947030', '80323', 0, '2024-04-16 11:22:41', 0, 1);
INSERT INTO `forum_comment` VALUES (10050, 10048, 'X4VPEb3ShoUYAVT', '别读了', NULL, '3764947030', '80323', '江西省', '3764947030', '80323', 0, '2024-04-16 11:22:56', 0, 1);
INSERT INTO `forum_comment` VALUES (10051, 10048, 'X4VPEb3ShoUYAVT', '禁止作者自娱自乐', NULL, '7183809612', '我还是走开发吧', '江西省', '3764947030', '80323', 0, '2024-04-16 15:43:26', 0, -1);
INSERT INTO `forum_comment` VALUES (10052, 0, 'X4VPEb3ShoUYAVT', '算法狗看了都摇头', '202404/uSopkd4ZZ30rKkp.jpg', '7183809612', '我还是走开发吧', '江西省', '', NULL, 0, '2024-04-16 15:44:35', 1, -1);
INSERT INTO `forum_comment` VALUES (10053, 0, 'aYa8yjvk4fxMbYM', '666', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2024-07-04 22:11:43', 0, 1);
INSERT INTO `forum_comment` VALUES (10054, 0, 'aYa8yjvk4fxMbYM', '666', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2024-07-04 22:12:18', 0, 1);
INSERT INTO `forum_comment` VALUES (10055, 0, 'aYa8yjvk4fxMbYM', '666', NULL, '6783480097', 'kkk', '江西省', '', NULL, 0, '2024-07-04 22:12:40', 0, 1);

-- ----------------------------
-- Table structure for like_record
-- ----------------------------
DROP TABLE IF EXISTS `like_record`;
CREATE TABLE `like_record`  (
  `op_id` int(11) NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `op_type` tinyint(4) NULL DEFAULT NULL COMMENT '操作类型0:文章点赞 1:评论点赞',
  `object_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '主体ID',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户ID',
  `create_time` datetime NULL DEFAULT NULL COMMENT '发布时间',
  `author_user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '主体作者ID',
  PRIMARY KEY (`op_id`) USING BTREE,
  UNIQUE INDEX `idx_key`(`object_id`, `user_id`, `op_type`) USING BTREE,
  INDEX `idx_user_id`(`user_id`, `op_type`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10066 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '点赞记录' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of like_record
-- ----------------------------
INSERT INTO `like_record` VALUES (10000, 0, 'RtiXj832TFL4nhW', '7437465925', '2023-01-16 09:53:50', '1890524956');
INSERT INTO `like_record` VALUES (10003, 1, '10007', '6783480097', '2023-11-08 20:57:28', '6783480097');
INSERT INTO `like_record` VALUES (10005, 1, '10004', '6783480097', '2023-11-15 20:42:27', '6783480097');
INSERT INTO `like_record` VALUES (10006, 1, '10008', '6783480097', '2023-11-15 20:42:28', '6783480097');
INSERT INTO `like_record` VALUES (10007, 1, '10005', '6783480097', '2023-11-15 20:42:29', '6783480097');
INSERT INTO `like_record` VALUES (10008, 1, '10001', '6783480097', '2023-11-15 20:42:33', '1890524956');
INSERT INTO `like_record` VALUES (10013, 0, 'RtiXj832TFL4nhW', '6783480097', '2023-11-15 21:01:17', '1890524956');
INSERT INTO `like_record` VALUES (10015, 0, 'fj8Fm1KHg8vWywx', '6783480097', '2023-11-15 21:50:16', '6783480097');
INSERT INTO `like_record` VALUES (10017, 0, 'fj8Fm1KHg8vWywx', '7430015025', '2023-11-15 21:53:12', '6783480097');
INSERT INTO `like_record` VALUES (10018, 0, '0XHRpvcW13aTVMu', '7430015025', '2023-11-15 21:57:35', '6783480097');
INSERT INTO `like_record` VALUES (10019, 0, 'U2zRa4cFPwLF4rR', '6783480097', '2023-11-15 22:23:59', '7437465925');
INSERT INTO `like_record` VALUES (10020, 1, '10011', '6783480097', '2023-11-15 22:49:58', '6783480097');
INSERT INTO `like_record` VALUES (10022, 0, 'CPWUe9ujqFHjthh', '7430015025', '2023-11-18 20:22:27', '7430015025');
INSERT INTO `like_record` VALUES (10023, 1, '10016', '7430015025', '2023-11-18 20:23:14', '7430015025');
INSERT INTO `like_record` VALUES (10024, 0, 'CPWUe9ujqFHjthh', '6783480097', '2023-11-18 20:25:23', '7430015025');
INSERT INTO `like_record` VALUES (10025, 0, 'PYjST0gDQMZz4JJ', '3764947030', '2023-11-19 15:35:44', '3764947030');
INSERT INTO `like_record` VALUES (10027, 0, 'ylOlffcmY8BWjj8', '3764947030', '2023-11-19 15:41:48', '3764947030');
INSERT INTO `like_record` VALUES (10028, 0, 'ylOlffcmY8BWjj8', '6783480097', '2023-11-19 17:53:03', '3764947030');
INSERT INTO `like_record` VALUES (10029, 1, '10023', '6783480097', '2023-11-19 17:53:25', '6783480097');
INSERT INTO `like_record` VALUES (10030, 1, '10018', '6783480097', '2023-11-19 17:53:27', '3764947030');
INSERT INTO `like_record` VALUES (10031, 0, 'Rs8QJRZKUxdd079', '7430015025', '2023-11-19 20:50:48', '7430015025');
INSERT INTO `like_record` VALUES (10034, 1, '10014', '7430015025', '2023-11-19 21:37:07', '7430015025');
INSERT INTO `like_record` VALUES (10035, 1, '10021', '7430015025', '2023-11-19 21:37:12', '6783480097');
INSERT INTO `like_record` VALUES (10036, 1, '10024', '7430015025', '2023-11-19 21:38:49', '7430015025');
INSERT INTO `like_record` VALUES (10037, 1, '10026', '3159491214', '2023-11-21 19:16:40', '3159491214');
INSERT INTO `like_record` VALUES (10039, 1, '10014', '3159491214', '2023-11-21 19:24:10', '7430015025');
INSERT INTO `like_record` VALUES (10041, 1, '10014', '6783480097', '2023-11-21 21:22:36', '7430015025');
INSERT INTO `like_record` VALUES (10043, 1, '10032', '6783480097', '2023-11-21 21:29:43', '6783480097');
INSERT INTO `like_record` VALUES (10044, 1, '10020', '6783480097', '2023-11-21 21:29:45', '6783480097');
INSERT INTO `like_record` VALUES (10045, 1, '10021', '6783480097', '2023-11-21 21:29:45', '6783480097');
INSERT INTO `like_record` VALUES (10046, 0, '0XHRpvcW13aTVMu', '3159491214', '2023-11-21 21:40:43', '6783480097');
INSERT INTO `like_record` VALUES (10048, 1, '10035', '6783480097', '2023-11-21 21:46:43', '6783480097');
INSERT INTO `like_record` VALUES (10050, 0, 'AXY6tGgAKwOUBEn', '6783480097', '2023-11-21 22:40:07', '3159491214');
INSERT INTO `like_record` VALUES (10051, 0, '0XHRpvcW13aTVMu', '3764947030', '2023-11-25 00:41:44', '6783480097');
INSERT INTO `like_record` VALUES (10052, 1, '10034', '6783480097', '2024-03-10 14:22:59', '3159491214');
INSERT INTO `like_record` VALUES (10053, 1, '10030', '6783480097', '2024-03-10 14:23:00', '6783480097');
INSERT INTO `like_record` VALUES (10054, 0, '0XHRpvcW13aTVMu', '6783480097', '2024-03-11 15:52:38', '6783480097');
INSERT INTO `like_record` VALUES (10055, 0, 'X4VPEb3ShoUYAVT', '6783480097', '2024-04-03 18:55:54', '3764947030');
INSERT INTO `like_record` VALUES (10056, 0, 'bEEIzLEU5STfoRt', '6783480097', '2024-04-03 19:05:31', '6783480097');
INSERT INTO `like_record` VALUES (10057, 0, 'F799DOp4DbbmjtS', '6783480097', '2024-04-05 01:13:35', '6783480097');
INSERT INTO `like_record` VALUES (10058, 1, '10044', '7430015025', '2024-04-08 19:42:35', '6783480097');
INSERT INTO `like_record` VALUES (10060, 0, 'X4VPEb3ShoUYAVT', '3764947030', '2024-04-16 11:21:17', '3764947030');
INSERT INTO `like_record` VALUES (10062, 1, '10047', '3764947030', '2024-04-16 11:22:23', '3764947030');
INSERT INTO `like_record` VALUES (10063, 1, '10048', '3764947030', '2024-04-16 11:22:59', '3764947030');
INSERT INTO `like_record` VALUES (10064, 0, 'X4VPEb3ShoUYAVT', '7183809612', '2024-04-16 15:43:09', '3764947030');
INSERT INTO `like_record` VALUES (10065, 1, '10052', '7183809612', '2024-04-16 15:44:38', '7183809612');

-- ----------------------------
-- Table structure for record_article
-- ----------------------------
DROP TABLE IF EXISTS `record_article`;
CREATE TABLE `record_article`  (
  `record_id` varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '浏览过的文章id'
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of record_article
-- ----------------------------

-- ----------------------------
-- Table structure for sys_setting
-- ----------------------------
DROP TABLE IF EXISTS `sys_setting`;
CREATE TABLE `sys_setting`  (
  `code` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '编号',
  `json_content` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '设置信息',
  PRIMARY KEY (`code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统设置信息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of sys_setting
-- ----------------------------
INSERT INTO `sys_setting` VALUES ('audit', '{\"commentAudit\":false,\"postAudit\":true}');
INSERT INTO `sys_setting` VALUES ('comment', '{\"commentDayCountThreshold\":50,\"commentIntegral\":1,\"commentOpen\":true}');
INSERT INTO `sys_setting` VALUES ('email', '{\"emailContent\":\"你好，您的邮箱验证码是：%s，15分钟有效\",\"emailTitle\":\"邮箱验证码--知享乐园\"}');
INSERT INTO `sys_setting` VALUES ('like', '{\"likeDayCountThreshold\":50}');
INSERT INTO `sys_setting` VALUES ('post', '{\"attachmentSize\":1,\"dayImageUploadCount\":50,\"postDayCountThreshold\":50,\"postIntegral\":1}');
INSERT INTO `sys_setting` VALUES ('register', '{\"registerWelcomInfo\":\"欢迎来到知享乐园，在这里，你可以和各位卷王一起学习交流，互相分享学习资源或经验。\"}');

-- ----------------------------
-- Table structure for user_info
-- ----------------------------
DROP TABLE IF EXISTS `user_info`;
CREATE TABLE `user_info`  (
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户ID',
  `nick_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '昵称',
  `email` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '邮箱',
  `password` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '密码',
  `sex` tinyint(1) NULL DEFAULT NULL COMMENT '0:女 1:男',
  `person_description` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '个人描述',
  `join_time` datetime NULL DEFAULT NULL COMMENT '加入时间',
  `last_login_time` datetime NULL DEFAULT NULL COMMENT '最后登录时间',
  `last_login_ip` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '最后登录IP',
  `last_login_ip_address` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '最后登录ip地址',
  `total_integral` int(11) NULL DEFAULT NULL COMMENT '积分',
  `current_integral` int(11) NULL DEFAULT NULL COMMENT '当前积分',
  `status` tinyint(4) NULL DEFAULT NULL COMMENT '0:禁用 1:正常',
  PRIMARY KEY (`user_id`) USING BTREE,
  UNIQUE INDEX `key_email`(`email`) USING BTREE,
  UNIQUE INDEX `key_nick_name`(`nick_name`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户信息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user_info
-- ----------------------------
INSERT INTO `user_info` VALUES ('3159491214', '念', '2935406165@qq.com', '290ed588971a1f649d95e6a96676c260', 1, '卷王卷王', '2023-11-21 18:59:38', '2023-11-21 21:44:37', '0:0:0:0:0:0:0:1', '江西省', 17, 13, 1);
INSERT INTO `user_info` VALUES ('3764947030', '80323', '3222723170@qq.com', '290ed588971a1f649d95e6a96676c260', 1, '104第一摆烂王', '2023-11-19 15:31:42', '2024-04-16 11:21:04', '183.217.29.165', '江西省', 29, 26, 1);
INSERT INTO `user_info` VALUES ('6783480097', 'kkk', '2765314967@qq.com', '290ed588971a1f649d95e6a96676c260', 1, '', '2023-11-07 21:56:10', '2024-07-04 22:11:09', '39.144.168.16', '江西省', 465, 453, 1);
INSERT INTO `user_info` VALUES ('7183809612', '我还是走开发吧', '2629152500@qq.com', '290ed588971a1f649d95e6a96676c260', 1, '', '2024-04-16 15:42:06', '2024-04-16 16:22:50', '183.217.29.165', '江西省', 7, 2, 1);
INSERT INTO `user_info` VALUES ('7430015025', 'kkky', '2661727280@qq.com', 'dbca8a00042a699dd533cf8789b7e610', 1, '旧时浮尘', '2023-11-15 21:52:34', '2024-04-08 19:39:07', '183.217.25.143', '江西省', 21, 21, 1);

-- ----------------------------
-- Table structure for user_integral_record
-- ----------------------------
DROP TABLE IF EXISTS `user_integral_record`;
CREATE TABLE `user_integral_record`  (
  `record_id` int(11) NOT NULL AUTO_INCREMENT COMMENT '记录ID',
  `user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '用户ID',
  `oper_type` tinyint(4) NULL DEFAULT NULL COMMENT '操作类型',
  `integral` int(11) NULL DEFAULT NULL COMMENT '积分',
  `create_time` datetime NULL DEFAULT NULL COMMENT '创建时间',
  PRIMARY KEY (`record_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10129 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户积分记录表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user_integral_record
-- ----------------------------
INSERT INTO `user_integral_record` VALUES (10000, '1890524956', 1, 5, '2023-01-15 17:45:46');
INSERT INTO `user_integral_record` VALUES (10004, '1890524956', 4, 1, '2023-01-15 18:01:23');
INSERT INTO `user_integral_record` VALUES (10005, '1890524956', 4, 1, '2023-01-15 18:01:35');
INSERT INTO `user_integral_record` VALUES (10006, '1890524956', 4, 1, '2023-01-16 09:26:07');
INSERT INTO `user_integral_record` VALUES (10007, '1890524956', 4, 1, '2023-01-16 09:31:13');
INSERT INTO `user_integral_record` VALUES (10008, '1890524956', 4, 1, '2023-01-16 09:34:14');
INSERT INTO `user_integral_record` VALUES (10009, '1890524956', 4, 1, '2023-01-16 09:34:34');
INSERT INTO `user_integral_record` VALUES (10010, '1890524956', 4, 1, '2023-01-16 09:34:52');
INSERT INTO `user_integral_record` VALUES (10011, '1890524956', 4, 1, '2023-01-16 09:35:14');
INSERT INTO `user_integral_record` VALUES (10012, '7437465925', 1, 5, '2023-01-16 09:52:31');
INSERT INTO `user_integral_record` VALUES (10013, '7437465925', 4, 1, '2023-01-16 09:54:04');
INSERT INTO `user_integral_record` VALUES (10014, '7437465925', 4, 1, '2023-01-16 09:55:37');
INSERT INTO `user_integral_record` VALUES (10015, '7437465925', 4, 1, '2023-01-16 09:57:32');
INSERT INTO `user_integral_record` VALUES (10016, '7437465925', 4, 1, '2023-01-16 09:58:13');
INSERT INTO `user_integral_record` VALUES (10017, '7437465925', 4, 1, '2023-01-16 09:58:54');
INSERT INTO `user_integral_record` VALUES (10018, '7437465925', 4, 1, '2023-01-16 09:59:37');
INSERT INTO `user_integral_record` VALUES (10019, '7437465925', 4, 1, '2023-01-16 10:00:19');
INSERT INTO `user_integral_record` VALUES (10020, '7437465925', 4, 1, '2023-01-16 10:01:14');
INSERT INTO `user_integral_record` VALUES (10021, '7437465925', 4, 1, '2023-01-16 10:01:43');
INSERT INTO `user_integral_record` VALUES (10022, '7437465925', 4, 1, '2023-01-16 10:02:53');
INSERT INTO `user_integral_record` VALUES (10023, '7437465925', 4, 1, '2023-01-16 10:05:02');
INSERT INTO `user_integral_record` VALUES (10024, '7437465925', 4, 1, '2023-01-16 10:09:28');
INSERT INTO `user_integral_record` VALUES (10025, '7437465925', 4, 1, '2023-01-16 14:43:28');
INSERT INTO `user_integral_record` VALUES (10026, '6783480097', 1, 5, '2023-11-07 21:56:10');
INSERT INTO `user_integral_record` VALUES (10027, '6783480097', 4, 1, '2023-11-07 21:56:53');
INSERT INTO `user_integral_record` VALUES (10028, '6783480097', 4, 1, '2023-11-07 21:59:22');
INSERT INTO `user_integral_record` VALUES (10029, '6783480097', 4, 1, '2023-11-07 22:36:33');
INSERT INTO `user_integral_record` VALUES (10030, '6783480097', 4, 1, '2023-11-07 22:36:48');
INSERT INTO `user_integral_record` VALUES (10031, '7437465925', 8, -1, '2023-11-08 17:38:15');
INSERT INTO `user_integral_record` VALUES (10032, '6783480097', 4, 1, '2023-11-08 20:57:25');
INSERT INTO `user_integral_record` VALUES (10033, '6783480097', 4, 1, '2023-11-08 23:10:19');
INSERT INTO `user_integral_record` VALUES (10034, '6783480097', 6, 1, '2023-11-08 23:13:28');
INSERT INTO `user_integral_record` VALUES (10035, '6783480097', 5, 1, '2023-11-14 21:08:44');
INSERT INTO `user_integral_record` VALUES (10036, '7430015025', 1, 5, '2023-11-15 21:52:34');
INSERT INTO `user_integral_record` VALUES (10037, '6783480097', 4, 1, '2023-11-15 21:54:13');
INSERT INTO `user_integral_record` VALUES (10038, '6783480097', 4, 1, '2023-11-15 22:46:50');
INSERT INTO `user_integral_record` VALUES (10039, '6783480097', 4, 1, '2023-11-15 22:49:54');
INSERT INTO `user_integral_record` VALUES (10040, '6783480097', 4, 1, '2023-11-15 22:50:06');
INSERT INTO `user_integral_record` VALUES (10041, '6783480097', 4, 1, '2023-11-15 22:50:10');
INSERT INTO `user_integral_record` VALUES (10042, '7430015025', 4, 1, '2023-11-18 19:53:16');
INSERT INTO `user_integral_record` VALUES (10043, '7430015025', 4, 1, '2023-11-18 20:21:43');
INSERT INTO `user_integral_record` VALUES (10044, '7430015025', 4, 1, '2023-11-18 20:22:55');
INSERT INTO `user_integral_record` VALUES (10045, '7430015025', 4, 1, '2023-11-18 20:23:12');
INSERT INTO `user_integral_record` VALUES (10046, '6783480097', 4, 1, '2023-11-18 20:25:03');
INSERT INTO `user_integral_record` VALUES (10047, '6783480097', 2, -5, '2023-11-18 20:25:46');
INSERT INTO `user_integral_record` VALUES (10048, '7430015025', 3, 5, '2023-11-18 20:25:46');
INSERT INTO `user_integral_record` VALUES (10049, '7430015025', 4, 1, '2023-11-18 20:29:01');
INSERT INTO `user_integral_record` VALUES (10050, '6783480097', 4, 1, '2023-11-18 20:40:16');
INSERT INTO `user_integral_record` VALUES (10051, '3764947030', 1, 5, '2023-11-19 15:31:42');
INSERT INTO `user_integral_record` VALUES (10052, '3764947030', 4, 1, '2023-11-19 15:35:35');
INSERT INTO `user_integral_record` VALUES (10053, '3764947030', 4, 1, '2023-11-19 15:41:42');
INSERT INTO `user_integral_record` VALUES (10054, '3764947030', 4, 1, '2023-11-19 15:41:54');
INSERT INTO `user_integral_record` VALUES (10055, '3764947030', 4, 1, '2023-11-19 15:45:23');
INSERT INTO `user_integral_record` VALUES (10056, '3764947030', 4, 1, '2023-11-19 15:47:21');
INSERT INTO `user_integral_record` VALUES (10057, '6783480097', 4, 1, '2023-11-19 17:49:31');
INSERT INTO `user_integral_record` VALUES (10058, '6783480097', 4, 1, '2023-11-19 17:49:39');
INSERT INTO `user_integral_record` VALUES (10059, '6783480097', 4, 1, '2023-11-19 17:49:55');
INSERT INTO `user_integral_record` VALUES (10060, '6783480097', 4, 1, '2023-11-19 17:53:10');
INSERT INTO `user_integral_record` VALUES (10061, '6783480097', 4, 1, '2023-11-19 17:53:22');
INSERT INTO `user_integral_record` VALUES (10062, '7430015025', 4, 1, '2023-11-19 21:38:42');
INSERT INTO `user_integral_record` VALUES (10063, '3764947030', 6, 1, '2023-11-19 22:08:10');
INSERT INTO `user_integral_record` VALUES (10064, '6783480097', 2, -5, '2023-11-19 22:13:24');
INSERT INTO `user_integral_record` VALUES (10065, '3764947030', 3, 5, '2023-11-19 22:13:24');
INSERT INTO `user_integral_record` VALUES (10066, '3764947030', 4, 1, '2023-11-19 22:33:03');
INSERT INTO `user_integral_record` VALUES (10067, '3764947030', 8, -1, '2023-11-19 22:33:10');
INSERT INTO `user_integral_record` VALUES (10068, '3159491214', 1, 5, '2023-11-21 18:59:38');
INSERT INTO `user_integral_record` VALUES (10069, '3159491214', 5, 1, '2023-11-21 19:16:06');
INSERT INTO `user_integral_record` VALUES (10070, '3159491214', 4, 1, '2023-11-21 19:16:37');
INSERT INTO `user_integral_record` VALUES (10071, '3159491214', 4, 1, '2023-11-21 19:24:17');
INSERT INTO `user_integral_record` VALUES (10072, '3159491214', 4, 1, '2023-11-21 19:24:26');
INSERT INTO `user_integral_record` VALUES (10073, '6783480097', 5, 1, '2023-11-21 19:28:48');
INSERT INTO `user_integral_record` VALUES (10074, '3159491214', 8, -1, '2023-11-21 19:29:12');
INSERT INTO `user_integral_record` VALUES (10075, '3159491214', 6, 5, '2023-11-21 19:30:33');
INSERT INTO `user_integral_record` VALUES (10076, '6783480097', 5, 1, '2023-11-21 20:03:37');
INSERT INTO `user_integral_record` VALUES (10077, '6783480097', 5, 1, '2023-11-21 20:07:38');
INSERT INTO `user_integral_record` VALUES (10078, '3159491214', 4, 1, '2023-11-21 21:16:44');
INSERT INTO `user_integral_record` VALUES (10079, '6783480097', 4, 1, '2023-11-21 21:20:14');
INSERT INTO `user_integral_record` VALUES (10080, '6783480097', 4, 1, '2023-11-21 21:20:29');
INSERT INTO `user_integral_record` VALUES (10081, '6783480097', 5, 1, '2023-11-21 21:21:28');
INSERT INTO `user_integral_record` VALUES (10082, '6783480097', 6, 5, '2023-11-21 21:23:44');
INSERT INTO `user_integral_record` VALUES (10083, '6783480097', 4, 1, '2023-11-21 21:29:41');
INSERT INTO `user_integral_record` VALUES (10084, '6783480097', 4, 1, '2023-11-21 21:29:52');
INSERT INTO `user_integral_record` VALUES (10085, '6783480097', 5, 1, '2023-11-21 21:33:22');
INSERT INTO `user_integral_record` VALUES (10086, '6783480097', 8, -1, '2023-11-21 21:33:54');
INSERT INTO `user_integral_record` VALUES (10087, '7430015025', 6, 3, '2023-11-21 21:34:38');
INSERT INTO `user_integral_record` VALUES (10088, '3159491214', 4, 1, '2023-11-21 21:40:56');
INSERT INTO `user_integral_record` VALUES (10089, '3159491214', 2, -3, '2023-11-21 21:42:17');
INSERT INTO `user_integral_record` VALUES (10090, '6783480097', 3, 3, '2023-11-21 21:42:17');
INSERT INTO `user_integral_record` VALUES (10091, '6783480097', 4, 1, '2023-11-21 21:46:28');
INSERT INTO `user_integral_record` VALUES (10092, '6783480097', 4, 1, '2023-11-21 21:46:33');
INSERT INTO `user_integral_record` VALUES (10093, '6783480097', 4, 1, '2023-11-21 21:46:36');
INSERT INTO `user_integral_record` VALUES (10094, '6783480097', 5, 1, '2023-11-21 21:48:36');
INSERT INTO `user_integral_record` VALUES (10095, '6783480097', 8, -1, '2023-11-21 21:49:20');
INSERT INTO `user_integral_record` VALUES (10096, '6783480097', 6, 5, '2023-11-21 21:50:00');
INSERT INTO `user_integral_record` VALUES (10097, '6783480097', 4, 1, '2023-11-21 22:40:14');
INSERT INTO `user_integral_record` VALUES (10098, '6783480097', 5, 1, '2023-11-21 22:42:18');
INSERT INTO `user_integral_record` VALUES (10099, '3159491214', 6, 1, '2023-11-21 22:44:00');
INSERT INTO `user_integral_record` VALUES (10100, '6783480097', 6, 2, '2023-11-22 21:23:39');
INSERT INTO `user_integral_record` VALUES (10101, '3764947030', 4, 1, '2023-11-25 00:41:49');
INSERT INTO `user_integral_record` VALUES (10102, '3764947030', 4, 1, '2023-11-25 00:43:03');
INSERT INTO `user_integral_record` VALUES (10103, '3764947030', 5, 1, '2023-11-25 00:44:16');
INSERT INTO `user_integral_record` VALUES (10104, '3764947030', 8, -1, '2023-11-25 00:44:46');
INSERT INTO `user_integral_record` VALUES (10105, '6783480097', 4, 1, '2024-03-10 14:22:55');
INSERT INTO `user_integral_record` VALUES (10106, '6783480097', 4, 1, '2024-03-11 15:52:48');
INSERT INTO `user_integral_record` VALUES (10107, '3764947030', 7, -1, '2024-04-03 18:45:14');
INSERT INTO `user_integral_record` VALUES (10108, '6783480097', 4, 1, '2024-04-03 19:05:38');
INSERT INTO `user_integral_record` VALUES (10109, '6783480097', 4, 1, '2024-04-03 19:07:28');
INSERT INTO `user_integral_record` VALUES (10110, '6783480097', 5, 1, '2024-04-03 19:16:27');
INSERT INTO `user_integral_record` VALUES (10111, '6783480097', 5, 1, '2024-04-05 01:13:27');
INSERT INTO `user_integral_record` VALUES (10112, '6783480097', 4, 1, '2024-04-05 14:09:45');
INSERT INTO `user_integral_record` VALUES (10113, '7430015025', 4, 1, '2024-04-08 19:43:23');
INSERT INTO `user_integral_record` VALUES (10114, '7430015025', 4, 1, '2024-04-08 19:43:29');
INSERT INTO `user_integral_record` VALUES (10115, '3764947030', 4, 1, '2024-04-16 11:21:57');
INSERT INTO `user_integral_record` VALUES (10116, '3764947030', 4, 1, '2024-04-16 11:22:14');
INSERT INTO `user_integral_record` VALUES (10117, '3764947030', 4, 1, '2024-04-16 11:22:41');
INSERT INTO `user_integral_record` VALUES (10118, '3764947030', 4, 1, '2024-04-16 11:22:56');
INSERT INTO `user_integral_record` VALUES (10119, '7183809612', 1, 5, '2024-04-16 15:42:06');
INSERT INTO `user_integral_record` VALUES (10120, '7183809612', 4, 1, '2024-04-16 15:43:26');
INSERT INTO `user_integral_record` VALUES (10121, '7183809612', 4, 1, '2024-04-16 15:44:35');
INSERT INTO `user_integral_record` VALUES (10122, '7183809612', 2, -5, '2024-04-16 15:44:51');
INSERT INTO `user_integral_record` VALUES (10123, '3764947030', 3, 5, '2024-04-16 15:44:51');
INSERT INTO `user_integral_record` VALUES (10124, '6783480097', 6, 200, '2024-04-16 16:26:42');
INSERT INTO `user_integral_record` VALUES (10125, '6783480097', 6, 200, '2024-04-16 16:27:50');
INSERT INTO `user_integral_record` VALUES (10126, '6783480097', 4, 1, '2024-07-04 22:11:44');
INSERT INTO `user_integral_record` VALUES (10127, '6783480097', 4, 1, '2024-07-04 22:12:18');
INSERT INTO `user_integral_record` VALUES (10128, '6783480097', 4, 1, '2024-07-04 22:12:40');

-- ----------------------------
-- Table structure for user_message
-- ----------------------------
DROP TABLE IF EXISTS `user_message`;
CREATE TABLE `user_message`  (
  `message_id` int(11) NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `received_user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '接收人用户ID',
  `article_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '文章ID',
  `article_title` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '文章标题',
  `comment_id` int(11) NULL DEFAULT NULL COMMENT '评论ID',
  `send_user_id` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '发送人用户ID',
  `send_nick_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '发送人昵称',
  `message_type` tinyint(4) NULL DEFAULT NULL COMMENT '0:系统消息 1:评论 2:文章点赞  3:评论点赞 4:附件下载',
  `message_content` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '消息内容',
  `status` tinyint(4) NULL DEFAULT NULL COMMENT '1:未读 2:已读',
  `create_time` datetime NULL DEFAULT NULL COMMENT '创建时间',
  PRIMARY KEY (`message_id`) USING BTREE,
  UNIQUE INDEX `idx_key`(`article_id`, `comment_id`, `send_user_id`, `message_type`) USING BTREE,
  INDEX `idx_received_user_id`(`received_user_id`) USING BTREE,
  INDEX `idx_status`(`status`) USING BTREE,
  INDEX `idx_type`(`message_type`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10082 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户消息' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user_message
-- ----------------------------
INSERT INTO `user_message` VALUES (10006, '1890524956', 'RtiXj832TFL4nhW', '第一个帖子，带图，带附件', 10000, '6783480097', 'kkk', 3, '自己做沙发', 1, '2023-11-07 21:56:47');
INSERT INTO `user_message` VALUES (10007, '1890524956', 'RtiXj832TFL4nhW', '第一个帖子，带图，带附件', 10004, '6783480097', 'kkk', 1, '6666666', 1, '2023-11-07 21:56:53');
INSERT INTO `user_message` VALUES (10008, '1890524956', 'RtiXj832TFL4nhW', '第一个帖子，带图，带附件', 0, '6783480097', 'kkk', 4, NULL, 1, '2023-11-08 16:55:38');
INSERT INTO `user_message` VALUES (10011, '1890524956', 'RtiXj832TFL4nhW', '第一个帖子，带图，带附件', 10001, '6783480097', 'kkk', 3, '带图的评论', 1, '2023-11-13 20:14:32');
INSERT INTO `user_message` VALUES (10014, '1890524956', 'RtiXj832TFL4nhW', '第一个帖子，带图，带附件', 0, '6783480097', 'kkk', 2, NULL, 1, '2023-11-15 21:01:17');
INSERT INTO `user_message` VALUES (10015, '7430015025', NULL, NULL, NULL, NULL, NULL, 0, '欢迎来到大学生资源分享平台，在这里，你可以和各位卷王一起学习交流，互相分享学习资源或经验。', 2, '2023-11-15 21:52:34');
INSERT INTO `user_message` VALUES (10016, '6783480097', 'fj8Fm1KHg8vWywx', '啊啊啊', 0, '7430015025', 'kkky', 2, NULL, 2, '2023-11-15 21:53:12');
INSERT INTO `user_message` VALUES (10017, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 0, '7430015025', 'kkky', 2, NULL, 2, '2023-11-15 21:57:35');
INSERT INTO `user_message` VALUES (10019, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10014, '7430015025', 'kkky', 1, '太棒了555', 2, '2023-11-18 19:53:16');
INSERT INTO `user_message` VALUES (10020, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10015, '7430015025', 'kkky', 1, '学废了学废了', 2, '2023-11-18 20:22:55');
INSERT INTO `user_message` VALUES (10021, '7430015025', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10017, '6783480097', 'kkk', 1, '哎哟你干嘛', 2, '2023-11-18 20:25:03');
INSERT INTO `user_message` VALUES (10022, '7430015025', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 0, '6783480097', 'kkk', 2, NULL, 2, '2023-11-18 20:25:23');
INSERT INTO `user_message` VALUES (10023, '7430015025', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 0, '6783480097', 'kkk', 4, NULL, 2, '2023-11-18 20:25:46');
INSERT INTO `user_message` VALUES (10024, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '欢迎来到知享乐园，在这里，你可以和各位卷王一起学习交流，互相分享学习资源或经验。', 2, '2023-11-19 15:31:42');
INSERT INTO `user_message` VALUES (10025, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 0, '3764947030', '80323', 2, NULL, 2, '2023-11-19 15:36:09');
INSERT INTO `user_message` VALUES (10026, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10020, '6783480097', 'kkk', 1, '哈哈哈', 2, '2023-11-19 17:49:39');
INSERT INTO `user_message` VALUES (10027, '3764947030', 'ylOlffcmY8BWjj8', '英语四级比计算机等级难多少,英语四级难考吗？学长：掌握方法，过“425”分不困难...', 0, '6783480097', 'kkk', 2, NULL, 2, '2023-11-19 17:53:03');
INSERT INTO `user_message` VALUES (10028, '3764947030', 'ylOlffcmY8BWjj8', '英语四级比计算机等级难多少,英语四级难考吗？学长：掌握方法，过“425”分不困难...', 10022, '6783480097', 'kkk', 1, '可以可以', 2, '2023-11-19 17:53:10');
INSERT INTO `user_message` VALUES (10029, '3764947030', 'ylOlffcmY8BWjj8', '英语四级比计算机等级难多少,英语四级难考吗？学长：掌握方法，过“425”分不困难...', 10023, '6783480097', 'kkk', 1, '哎哟你干嘛', 2, '2023-11-19 17:53:22');
INSERT INTO `user_message` VALUES (10030, '3764947030', 'ylOlffcmY8BWjj8', '英语四级比计算机等级难多少,英语四级难考吗？学长：掌握方法，过“425”分不困难...', 10018, '6783480097', 'kkk', 3, '666', 2, '2023-11-19 17:53:27');
INSERT INTO `user_message` VALUES (10031, '3764947030', 'PYjST0gDQMZz4JJ', '大模型会毁了初级程序员 —— 对话图灵奖得主 Joseph Sifakis | 新程序员', 0, '7430015025', 'kkky', 2, NULL, 2, '2023-11-19 20:51:12');
INSERT INTO `user_message` VALUES (10032, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10021, '7430015025', 'kkky', 3, '记得三连', 2, '2023-11-19 21:37:12');
INSERT INTO `user_message` VALUES (10033, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10024, '7430015025', 'kkky', 1, '这是一个图片评论', 2, '2023-11-19 21:38:42');
INSERT INTO `user_message` VALUES (10034, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '从后台发送的一条指定系统消息用于测试', 2, '2023-11-19 22:08:10');
INSERT INTO `user_message` VALUES (10035, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 0, '6783480097', 'kkk', 4, NULL, 2, '2023-11-19 22:13:24');
INSERT INTO `user_message` VALUES (10036, '7430015025', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10025, '3764947030', '80323', 1, '不好看', 2, '2023-11-19 22:33:03');
INSERT INTO `user_message` VALUES (10037, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '评论【不好看】被管理员删除', 2, '2023-11-19 22:33:10');
INSERT INTO `user_message` VALUES (10038, '3159491214', NULL, NULL, NULL, NULL, NULL, 0, '欢迎来到知享乐园，在这里，你可以和各位卷王一起学习交流，互相分享学习资源或经验。', 2, '2023-11-21 18:59:38');
INSERT INTO `user_message` VALUES (10039, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 0, '3159491214', '念', 2, NULL, 2, '2023-11-21 19:24:06');
INSERT INTO `user_message` VALUES (10040, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10014, '3159491214', '念', 3, '太棒了555', 2, '2023-11-21 19:24:10');
INSERT INTO `user_message` VALUES (10041, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10027, '3159491214', '念', 1, '666', 2, '2023-11-21 19:24:17');
INSERT INTO `user_message` VALUES (10042, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10028, '3159491214', '念', 1, '666', 2, '2023-11-21 19:24:27');
INSERT INTO `user_message` VALUES (10043, '3159491214', NULL, NULL, NULL, NULL, NULL, 0, '评论【666】被管理员删除', 2, '2023-11-21 19:29:12');
INSERT INTO `user_message` VALUES (10044, '3159491214', NULL, NULL, NULL, NULL, NULL, 0, '666', 2, '2023-11-21 19:30:33');
INSERT INTO `user_message` VALUES (10045, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10029, '3159491214', '念', 1, '666', 2, '2023-11-21 21:16:44');
INSERT INTO `user_message` VALUES (10046, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10031, '6783480097', 'kkk', 1, 'hhh<br>', 2, '2023-11-21 21:20:29');
INSERT INTO `user_message` VALUES (10047, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10014, '6783480097', 'kkk', 3, '太棒了555', 2, '2023-11-21 21:22:36');
INSERT INTO `user_message` VALUES (10048, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '666666666', 2, '2023-11-21 21:23:44');
INSERT INTO `user_message` VALUES (10049, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10033, '6783480097', 'kkk', 1, '666', 2, '2023-11-21 21:29:52');
INSERT INTO `user_message` VALUES (10050, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '评论【666】被管理员删除', 2, '2023-11-21 21:33:54');
INSERT INTO `user_message` VALUES (10051, '7430015025', NULL, NULL, NULL, NULL, NULL, 0, '555', 2, '2023-11-21 21:34:38');
INSERT INTO `user_message` VALUES (10053, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10034, '3159491214', '念', 1, 'hhh', 2, '2023-11-21 21:40:56');
INSERT INTO `user_message` VALUES (10054, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 0, '3159491214', '念', 4, NULL, 2, '2023-11-21 21:42:17');
INSERT INTO `user_message` VALUES (10055, '7430015025', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10036, '6783480097', 'kkk', 1, 'hhhh', 2, '2023-11-21 21:46:33');
INSERT INTO `user_message` VALUES (10056, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '评论【hhh】被管理员删除', 2, '2023-11-21 21:49:20');
INSERT INTO `user_message` VALUES (10057, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '555', 2, '2023-11-21 21:50:00');
INSERT INTO `user_message` VALUES (10058, '3159491214', 'AXY6tGgAKwOUBEn', '大家平时都是怎么学习的？', 0, '6783480097', 'kkk', 2, NULL, 1, '2023-11-21 22:40:07');
INSERT INTO `user_message` VALUES (10059, '3159491214', 'AXY6tGgAKwOUBEn', '大家平时都是怎么学习的？', 10038, '6783480097', 'kkk', 1, 'hhh', 1, '2023-11-21 22:40:14');
INSERT INTO `user_message` VALUES (10060, '3159491214', NULL, NULL, NULL, NULL, NULL, 0, '555555', 1, '2023-11-21 22:44:00');
INSERT INTO `user_message` VALUES (10061, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '5555', 2, '2023-11-22 21:23:39');
INSERT INTO `user_message` VALUES (10062, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '文章【测试文章】被管理员删除', 2, '2023-11-23 08:38:16');
INSERT INTO `user_message` VALUES (10064, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10039, '3764947030', '80323', 1, '666', 2, '2023-11-25 00:41:49');
INSERT INTO `user_message` VALUES (10065, '6783480097', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10040, '3764947030', '80323', 1, '666', 2, '2023-11-25 00:43:03');
INSERT INTO `user_message` VALUES (10066, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '评论【666】被管理员删除', 1, '2023-11-25 00:44:46');
INSERT INTO `user_message` VALUES (10067, '3159491214', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10034, '6783480097', 'kkk', 3, 'hhh', 1, '2024-03-10 14:22:59');
INSERT INTO `user_message` VALUES (10068, '3159491214', '0XHRpvcW13aTVMu', 'Spring Boot 整合SpringSecurity和JWT和Redis实现统一鉴权认证', 10042, '6783480097', 'kkk', 1, 'hhhh', 1, '2024-03-11 15:52:48');
INSERT INTO `user_message` VALUES (10069, '3764947030', NULL, NULL, NULL, NULL, NULL, 0, '文章【55555555】被管理员删除', 1, '2024-04-03 18:45:14');
INSERT INTO `user_message` VALUES (10070, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 0, '6783480097', 'kkk', 2, NULL, 1, '2024-04-03 18:55:54');
INSERT INTO `user_message` VALUES (10071, '7430015025', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10044, '6783480097', 'kkk', 1, '测试测试测', 2, '2024-04-03 19:07:28');
INSERT INTO `user_message` VALUES (10072, '6783480097', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10044, '7430015025', 'kkky', 3, '测试测试测', 1, '2024-04-08 19:42:35');
INSERT INTO `user_message` VALUES (10073, '6783480097', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10045, '7430015025', 'kkky', 1, '哈哈哈', 2, '2024-04-08 19:43:23');
INSERT INTO `user_message` VALUES (10074, '6783480097', 'CPWUe9ujqFHjthh', 'Web Worker的概念、用法、使用场景', 10046, '7430015025', 'kkky', 1, '你干嘛', 2, '2024-04-08 19:43:29');
INSERT INTO `user_message` VALUES (10075, '7183809612', NULL, NULL, NULL, NULL, NULL, 0, '欢迎来到知享乐园，在这里，你可以和各位卷王一起学习交流，互相分享学习资源或经验。', 2, '2024-04-16 15:42:06');
INSERT INTO `user_message` VALUES (10076, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 0, '7183809612', '我还是走开发吧', 2, NULL, 1, '2024-04-16 15:43:09');
INSERT INTO `user_message` VALUES (10077, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 10051, '7183809612', '我还是走开发吧', 1, '禁止作者自娱自乐', 1, '2024-04-16 15:43:26');
INSERT INTO `user_message` VALUES (10078, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 10052, '7183809612', '我还是走开发吧', 1, '算法狗看了都摇头', 1, '2024-04-16 15:44:35');
INSERT INTO `user_message` VALUES (10079, '3764947030', 'X4VPEb3ShoUYAVT', '【蓝桥杯】双非本科？大一大二不敢参加？这篇蓝桥全解析帮你打消疑虑轻松获奖【内附蓝桥资源和学习路线】', 0, '7183809612', '我还是走开发吧', 4, NULL, 1, '2024-04-16 15:44:51');
INSERT INTO `user_message` VALUES (10080, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '送你200分测试一下', 2, '2024-04-16 16:26:42');
INSERT INTO `user_message` VALUES (10081, '6783480097', NULL, NULL, NULL, NULL, NULL, 0, '再送200', 2, '2024-04-16 16:27:50');

SET FOREIGN_KEY_CHECKS = 1;
