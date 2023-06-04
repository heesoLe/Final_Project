<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 서비스 준비중</title>
<style>
	/* company_introduce.jsp UI */
	/* body부분 색상 변경 */
	body {
		background-color: rgb(240, 240, 242);
	}
	/* 메인 컨텐츠 부분 */
	#wrap {
		width: 570px;
		height: 340px;
		border-radius: 8px;
		background-color: white;
		position: fixed;
		top: 25%;
		left: 50%;
		transform: translate(-50%, 0);
	}
	/* 헤더 부분 */
	.header {
		width: 100%;
		height: 210px;
		margin-bottom: 10px;
	}
	/* 텍스트 부분 */
	.textBox {
		width: 350px;
		float: left;
		margin: 75px 0px 0px 30px;
	}
	/* 서비스 문구 */
	#service_text {
		font-weight: bolder;
		font-size: 35px;
	}
	#service_text2 {
		font-weight: 400;
		font-size: 35px;
	}
	/* 이미지 부분 */
	.imgBox {
		width: 160px;
		float: right;
	}
	/* 이미지 */
	#crying_lionImg {
		width: 150px;
		height: 200px;
	}
	/* 내용 텍스트 */
	.content {
		text-align: center;
		font-weight: 600;
		font-size: 17px;
	}
</style>
</head>
<body>
	<div id="wrap">
		<div class="container">
			<div class="header">
				<div class="textBox">
					<span id=service_text>서비스 준비중</span><span id=service_text2>입니다.</span>
				</div>
				<div class="imgBox">
					<img src="<%=request.getContextPath()%>/images/crying_lion.png" id="crying_lionImg" alt="우는 라이언">
				</div>
			</div>
			<div class="content">
				<p>보다 나은 서비스 제공을 위하여 페이지 준비중에 있습니다.<br>
				빠른 시일내에 준비하여 찾아뵙겠습니다.</p>
			</div>
		</div>
	</div>
</body>
</html>