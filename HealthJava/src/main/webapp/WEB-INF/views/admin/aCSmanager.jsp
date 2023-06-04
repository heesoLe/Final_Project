<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link	href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"	rel="stylesheet"	integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"	crossorigin="anonymous"><%-- CDN 절대링크 --%>
<script	src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"	integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN"	crossorigin="anonymous"></script><%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"	integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM="	crossorigin="anonymous"></script><%-- CDN 절대링크 --%>
<script	src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script><%-- CDN 절대링크 --%>

<title>PuppyHome 고객센터 관리 Page</title>

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
	
	footer {
		bottom: 0;
		z-index: 5;
		position: relative;
	}
	
	.wrap {
		margin-top: -110px;
		min-height: 100%;
		position: relative;
	}
	
	.main {
		width: 1400px;
		height: 2000px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 */
		position: relative;
		top: 105px;
		left: 50%;
		transform: translateX(-50%);
		background-color: white; /* 영역 보기 편하라고 배경색 지정함 : 하얀색 */
	}
	
	section {
		height: 2000px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 */
		/* background-color: rgb(236, 226, 202); 영역 보기 편하라고 배경색 지정함 : 연주황 */
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	
	#btn {
		border-color: #FC5400;
		background-color: #FC5400;
		color: #fff;
	}
	.manager{
		color : #FC5400;
		font-family: 'KIMM_Bold';
	}
	.csList01 {
		border: none;
		width: 1300px;
		height: 250px;
		border-top: 2px solid #FC5400;
		border-bottom: 2px solid #FC5400;
		font-family: 'KIMM_Bold';
	}
	.csList01 th {
		border-bottom: 1px solid #f5ad56;
	}
		
</style>
</head>
<body>
<%-- 전체 영역 --%>
	<div class="wrap">
	<%-- 헤더 영역 --%>
	<header><%-- header include --%>
		<jsp:include page="../include/header.jsp" />
	</header>
	<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
	<section>
		<div class="main">
		
		<div class="adminMainpage">	<%-- adminMainpage --%>
			<%-- admin 계정 --%>
			<h1 class="name" style="color: #fc9300">Admin Page</h1>
			<div class="profile_img" align="center">
			<%-- 이미지 클릭시 관리자 메인화면으로 이동 --%>
			<a href="admin_main"><img width="150px" height="190px" align="left" alt="adminImage" src="<%=request.getContextPath()%>/images/admin.png"> </a>

				<div class="meau" align="right" style="color: white;">
					<a href="admin_main">회원 관리</a> | 
					<a href="admin_CSBoard">문의 게시판</a> | 
					<a href="admin_GsList">상품 목록</a> 
						 </div>

				<h3 class="myinfo" align="left"><b>관리자 계정</b> <br>
				</h3> <div class="myinfo_date" align="left">가입일 : 2023.03.15.</div>	<br>
			</div> <%-- end profile_img : 이미지 div --%>
			</div> <%-- end adminMainpage : 관리자 계정 고정 --%>
			<p>

			<%-- 전체 틀 고객센터 관리 테이블 --%>
			<div class="manager">  <%-- manager  --%>
				<h3 align="center">&nbsp;고객&nbsp;센터&nbsp;관리</h3><p>

				<%-- 고객센터 관리 게시판 --%>
				<table class="csList01" width="1300px;">
					<tr>
						<th width="50" height="50">&nbsp;</th>
						<th width="100">번호</th>
						<th width="200">제목</th>
						<th width="200">등록일</th>
					</tr>
					
					<%-- <c:if test="${!empty cslist}">
					<c:forEach var="cs" items="${cslist}"> --%>
					<tr height="100">
					<td align="center">&nbsp;</td>
					<td align="center"><%--${cs.번호} --%></td>
					<td align="center"><%--${cs.제목} --%></td>
					<td align="center"><%--${cs.등록} --%></td>
					</tr>
					<%-- </c:forEach> </c:if>--%>
					</table>
					<p><p>
					<input type="submit"  name="#" id="btn" value="등록"  />


			</div> <%-- end  manager  --%>

		</div>
		<%-- top버튼 삭제 X --%>
		<div id="topBtn">
			<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
		</div>
	</section>
	<%-- 푸터 영역 --%>
	<footer>
		<!-- footer -->
		<jsp:include page="../include/footer.jsp" />
		<!-- footer 끝 -->
	</footer>
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
	</div> <%-- end wrap --%>
</body>
</html>