<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" href="style.css">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 로그인</title>

<style type="text/css">

	/* 폰트 CSS */
	@font-face {
		font-family: 'KIMM_Bold';
		src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
		font-weight: 700;
		font-style: normal;
	}
	/* 되도록 안건드리는 영역 */
	* {
		box-sizing: border-box;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		    font-family: KIMM_Bold;
	}
	html {
		height: 100%;
	}
	body {
		margin: 0px;
		height: 100%;
		padding: 0px;
	}
	header {
		width: 100%;
	    position: fixed;
		z-index: 2;
	}
	.wrap {
		margin-top: -110px;
	}
	.main { 
		width: 1400px;
		position : relative;
		top: 105px;
		left: 50%;
        transform: translateX( -50% );
		background-color: rgb(179, 255, 213);  /* 영역 보기 편하라고 배경색 지정함 : 연초록 */
		margin: 0px;
	}
	section {
		height: 100%;
		background-color: rgb(236, 226, 202); /* 영역 보기 편하라고 배경색 지정함 : 연주황 */
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
		height: 935px;
	}
	/* 캐러셀 */
	#carouselExampleControls {
		width: 1100px;
		position : relative;
		left: 50%;
        transform: translateX( -50% );
	}
	.social-login b {
		background-color: #FC5400;
		color: #fff;
		border: none;
		padding: 10px 20px;
		border-radius: 5px;
		cursor: pointer;
	}
	
	
/* Login form styling */
.login-form {
	background-color: white;
	border: 2px solid #b21949;
	padding: 20px;
	width: 450px;
	margin: 0 auto;
	margin-top:200px;
	margin-bottom:100px;
	text-align:left;
	border-radius: 5px;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.login-form h1 {
	text-align: center;
	margin-top: 0;
}

.login-form label {
	display: block;
	font-weight: bold;
	margin-bottom: 5px;
	
}

.login-form input[type="text"],
.login-form input[type="password"] {
	width: 410px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.login-form input[type="checkbox"] {
	margin-right: 5px;
}

.login-form button[type="submit"] {
	background-color: #b21949;
	color: #fff;
	border: none;
	padding: 10px 20px;
	border-radius: 5px;
	cursor: pointer;
	
}

.login_button {
	text-align: center;
	margin-top: 20px;
}

.login_button button {
	width: 300px;
	display: inline-block;
	background-color: #FC5400;
	color: #fff;
	padding: 10px 20px;
	border-radius: 5px;
	text-decoration: none;
	margin-right: 10px;
}


.forgot-password,
.forgot-username {
	margin-top: 10px;
	text-align: right;
}

.forgot-password a,
.forgot-username a {
	color: #9889a0;
	text-decoration: none;
	font-size: 12px;
}

.forgot-password,.forgot-username a:hover {
	color: #b21949;
}

.social-login {
	margin-top: 20px;
	text-align: center;
}

.social-login p {
	margin-bottom: 10px;
}

.social-login a {
	display: inline-block;
	background-color: #FC5400;
	color: #fff;
	padding: 10px 20px;
	border-radius: 5px;
	text-decoration: none;
	margin-right: 10px;
}

.signup {
	margin-top: 20px;
	text-align: center;
}

.signup a {
	color: #b21949;
	text-decoration: none;
}

/* Google web font CDN*/


.signup-form {
	background-color: #f2f2f2;
	padding: 20px;
	width: 450px;
	margin: 0 auto;
	margin-top:200px;
	margin-bottom:100px;
	text-align:left;
	border-radius: 5px;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.-form label {
	display: block;
	font-weight: bold;
	margin-bottom: 5px;
	
}


.field select {
	
	width: 190px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
   
    margin-bottom: 5px;
}

.signup-form input[type="email"] {
	width: 190px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
   
    margin-bottom: 5px;
}

.signup-form input[type="text"],
.signup-form input[type="password"],
.signup-form input[type="tel"],
.signup-form input[type="number"]
 {
	width: 410px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
    width: 100%;
    margin-bottom: 5px;
}

.signup-form input[type="button"],
.signup-form input[type="submit"] {
	background-color: #FC5400;
	color: #fff;
	border: none;
	padding: 5px 20px;
	border-radius: 5px;
	cursor: pointer;
	border: 1px solid #dadada;
    
    width: 100%;
    margin-bottom: 5px;
}

*{
    box-sizing: border-box; /*��泥댁�� 諛��ㅼ�ъ�댁�*/
    outline: none; /*focus ������ ����由� ���ㅺ� */
}

body{
    font-family: 'Noto Sans KR', sans-serif;
    font-size:10px;
    background-color: #f5f6f7;
    line-height: 1.5em;
    color : #222;
    margin: 0;
}

a{
    text-decoration: none;
    color: #222;
}

/*member sign in*/

.member h1{
	text-align: center;
	
}


.member .logo{
    /*濡�怨��� �대�몄��� �몃�쇱�� 釉�濡��대��源� 留�吏� �ㅽ�� ���� 釉�濡�����留� �� */
    display: block;
    margin :50px auto;
}

.member .field{
    margin :5px 0; /*����濡� 醫� ����二쇨린*/
}

.member b{
    /* border: 1px solid #000; */
    display: block; /*��吏� ���ы��湲� */
    margin-bottom: 5px;
}

/*input 以� radio �� width 媛� 100%硫� ������源� */




.member input[type=button],
.member input[type=submit]{
background-color: #FC5400;
color:#fff
}

.member input:focus, .member select:focus{
    border: 1px solid #2db400;
}

.field_id div {
    display: flex;
}

.field_id div input:nth-child(1){
    flex:2;
}

.field_id div input:nth-child(2){
    flex:1;
}

.field.birth div{ /*field �대㈃�� birth*/
    display: flex;
    gap:10px; /*媛�寃� 踰��ㅼ��� 怨듭��泥��� �ъ�⑺���� */
}

/* .field.birth div > * {  gap �ъ�⑺��嫄곕�� 媛��� �④낵瑜� 以� 
    flex:1;
} */

.field.tel-number div {
    display: flex;
}

.field.tel-number div input:nth-child(1){
    flex:2;
}

.field.tel-number div input:nth-child(2){
    flex:1;
}


.field.address div {
    display: flex;
}

.field.address div input:nth-child(1){
    flex:2;
}

.field.address div input:nth-child(2){
    flex:1;
}

</style>
<script type="text/javascript">

function login_check() {
	if ($.trim($("#login_id").val()) == "") {
		alert("로그인 아이디를 입력하세요!");
		$("#login_id").val("").focus();
		return false;
	}
	if ($.trim($("#login_pwd").val()) == "") {
		alert("로그인 비번을 입력하세요!");
		$("#login_pwd").val("").focus();
		return false;
	}
}//로그인 인증 유효성 검증

//비번찾기
function pwd_find() {
	$url = "pwd_find";//매핑주소
	window.open($url, "비번검색", "width=400px, height=300px, scrollbars=yes");
	//open(공지창경로,공지창이름,속성) 메서드로 폭이 300픽셀, 높이가 300픽셀, 스크롤바가 생성되는 새로운 공지창을 만든다.
}
</script>
</head>
<body>
<%
    
    Cookie[] cookies = request.getCookies();
    
  
    String user_Id = "";
    
    
    
    if(cookies != null) {
    	for(Cookie c : cookies) {
    		
    		if(c.getName().equals("login_id")) {
    			user_Id = c.getValue();
    		}
    	}
    }
    
    %>
	


	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
		<form method="post" action="member_login_ok" onsubmit="return login_check();">
		<div class="login-form">
		
		<h1>로그인</h1>
		
			<label for="username">아이디</label>
			<input type="text" value="<%=user_Id%>" name="login_id" id="login_id" required>
			
			<label for="password">비밀번호</label>
			<input type="password"  name="login_pwd" id="login_pwd"  style="font-family: '맑은 고딕', Arial, sans-serif;" required>
			
			
			<div>
			<label for="checkId">아이디 기억 <input type="checkbox" id="checkId" name="checkId" <% if(user_Id != null && !user_Id.isEmpty()) { %>checked<% } %>></label>
			</div>
		
		
			<div class="login_button" >
			<button type="submit">로그인</button>
			</div>
			
			<div class="kakao_button button" style="margin-left: 50px;">
			<a href="https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=aaaaee1f55c91d357e2043134c2a017c&redirect_uri=http://localhost:8282/kakao_callback">
			<img src="../images/kakao_button.png" /></a>
			</div>
			
			<div class="forgot-username">
				<a href="find_id">아이디 찾기</a> | <a href="find_pw_loginform">비밀번호 찾기</a>
			</div>
			
			
		
		
		<div class="signup">
			<p>계정이 없으신가요? <a href="member_join">회원가입</a></p>
		</div>
	</div>
	</form>





				<%-- top버튼 삭제 X --%>
				<div id="topBtn">
					<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
				</div>
			
			</section>
			<div class="clear"></div>
		<%-- 푸터 영역 --%>
		<footer>
			<!-- footer -->
			<jsp:include page="../include/footer.jsp" />
			<!-- footer 끝 -->
		</footer>
	</div>
	<script type="text/javascript">
	
		<%-- top버튼 부분 --%>
		// 클릭 이벤트 핸들러
		$("#topBtn").click(function(e) {
			e.stopPropagation();
			$("html, body").animate({
				scrollTop : 0
			}, 'fast', 'easeOutCubic');
		});

		// 스크롤 이벤트 핸들러
		$(window).scroll(function() {
			if ($(window).scrollTop() == 0) {
				$("#topBtn").css("opacity", 0); // TOP 버튼 숨기기
			} else {
				$("#topBtn").css("opacity", 1); // TOP 버튼 나타내기
			}
		});
		
	</script>
</body>
</html>