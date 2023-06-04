<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" href="style.css">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script>
<script
	src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script>
<%-- CDN 절대링크 --%>

<title>HealthJava 로그인</title>

<style type="text/css">

/* 폰트 CSS */
@font-face {
	font-family: 'KIMM_Bold';
	src:
		url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2')
		format('woff2'); /* CDN 절대링크  */
	font-weight: 700;
	font-style: normal;
}

body {
	font-family: Arial, sans-serif;
}

.container {
	max-width: 800px;
	margin: 0 auto;
	padding: 20px;
}

h1 {
	text-align: center;
}

h2 {
	margin-top: 30px;
}

.content {
	margin-bottom: 20px;
}

input[type="checkbox"] {
	margin-right: 10px;
}

button {
	display: block;
	margin: 0 auto;
	padding: 10px 20px;
	background-color: #007bff;
	color: #fff;
	border: none;
	border-radius: 4px;
	cursor: pointer;
}

button:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}
</style>


</head>
<body>



	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp" />
		</header>
		<div class="container">
			<h1>약관 동의</h1>
			<div class="content">
				<h2>이용 약관</h2>
				<p>약관 내용...</p>
				<label> <input type="checkbox" id="termsCheckbox">
					약관에 동의합니다.
				</label>
			</div>
			<div class="content">
				<h2>개인 정보 처리 방침</h2>
				<p>개인 정보 처리 방침 내용...</p>
				<label> <input type="checkbox" id="privacyCheckbox">
					개인 정보 처리 방침에 동의합니다.
				</label>
			</div>
			<button id="submitBtn" disabled>동의하기</button>
		</div>

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