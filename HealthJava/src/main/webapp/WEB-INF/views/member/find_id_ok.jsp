<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="https://developers.kakao.com/sdk/js/kakao.js"></script>
<script defer src="<%=request.getContextPath()%>/js/kakao.js"></script>
<script>Kakao.init('31d2f9dc79f327146c781ff55e8f8b76');</script>
<title></title>

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

	
	
	
	
	
	
.find-form {
	background-color: white;
	border: 2px solid #b21949;
	padding: 20px;
	width: 450px;
	margin: 0 auto;
	margin-top:200px;
	margin-bottom:225px;
	text-align:left;
	border-radius: 5px;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.find-form h1 {
	text-align: center;
	margin-top: 0;
}

.find-form label {
	display: block;
	font-weight: bold;
	margin-bottom: 5px;
	
}

.find-form input[type="text"]{
	width: 410px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}


.find-form button[type="submit"] {
	background-color: #b21949;
	color: #fff;
	border: none;
	padding: 10px 20px;
	border-radius: 5px;
	cursor: pointer;
	height: 48.75px;
	
}

.find_button {
	text-align: center;
	margin-top: 20px;
}

.find_button button {
	width: 150px;
	display: inline-block;
	background-color: #b21949;
	color: #fff;
	padding: 10px 20px;
	border-radius: 5px;
	text-decoration: none;
	margin-right: 10px;
	font-family: 'KIMM_Bold';
	border: solid #b21949;
}

.login_pwd_find {
	float_left: 10px;
}
.forgot-userphone,
.forgot-username {
	margin-top: 10px;
	text-align: right;
}

.forgot-userphone a,
.forgot-username a {
	color: #999;
	text-decoration: none;
	font-size: 12px;
}

.social-find {
	margin-top: 20px;
	text-align: center;
}

.social-find p {
	margin-bottom: 10px;
}

.social-find a {
	display: inline-block;
	background-color: #FC5400;
	color: #fff;
	padding: 10px 20px;
	border-radius: 5px;
	text-decoration: none;
	margin-right: 10px;
}





*{
    box-sizing: border-box; /*��泥댁�� 諛��ㅼ�ъ�댁�*/
    outline: none; /*focus ������ ����由� ���ㅺ� */
        font-family: KIMM_Bold;
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

	
</style>


</head>
<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
	
	<div class="find-form">
		<h1 style="font-family: 'KIMM_Bold'">아이디 찾기</h1>
		<form method="post" action="find_pw;">
			<label for="username">아이디</label>
			<input type="text" id="user_id" name="user_id" value="${findId}" readonly>
		
		<div class="find_button">
			<button type="button"  onclick="location='member_login';">로그인하기</button>
			<button type="submit" >비밀번호 찾기</button>
		</div>
		</form>
	</div>

	<%-- 푸터 영역 --%>
	<footer>
	
			<%-- header include --%>
			<jsp:include page="../include/footer.jsp"/>
		
	</footer>
	
	</div>

</body>
</html>