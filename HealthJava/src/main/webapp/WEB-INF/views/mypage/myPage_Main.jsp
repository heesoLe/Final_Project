<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" href="css/style.css">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 마이페이지</title>

<style type="text/css">
	/* 메인 컨텐츠 부분 */
	#wrap {
		width: 100%;
		height: 100%;
		text-align: center;
	}
	
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
		font-family: 'KIMM_Bold';
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
		font-family: 'KIMM_Bold';
		margin-top: -110px;
		min-height: 100%;
		position: relative;
	}
	
	.main {
		width: 1600px;
		height: 1200px;
		/* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / section이랑 px 맞춰야함 */
		position: relative;
		top: 105px;
		left: 50%;
		transform: translateX(-50%);
	}
	
	section {
		height: 1200px;
		/*UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함  .main이랑 px 맞춰야함*/
	}
	
	/* 클리어 */
	.clear {
		clear: both;
	}
	
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
		margin: 20px 0px;
	}
	
	/******************************************************************/
	
	/*MyPage_Main CSS*/
	table {
		border-collapse: collapse;
		border-spacing: 0;
	}
	
	section.notice {
		padding: 20px 0;
		/*추가*/
		/*width: 1200px;*/
		height: 200px;
		margin: 2px;
	}
	/*사이드바 스타일*/
	.aside_left {
		margin-top: 45px;
		margin-left: 60px;
		width: 180px;
		min-height: 700px;
		float: left;
		text-align: left;
	}
	
	.aside_left nav {
		min-height: 600px;
		margin-bottom: 50px;
	}
	
	.aside_left li {
		padding-top: 8.2px;
		padding-bottom: 2px;
		list-style: none;
	}
	
	li {
		padding-top: 10px;
	}
	
	nav {
		min-height: 600px;
		margin-bottom: 50px;
	}
	
	#subspan {
		color: #808080;
	}
	
	div.page-title {
		width: 1000px;
		min-height: 10px;
		padding: 0px 10px;
		text-align: left;
	}
	
	h3.page-title {
		font-size: 25px;
		color: black;
		font-weight: 400;
		text-align: left;
	}
	
	.memBasicInfo {
		height: 120px;
		padding: 20px;
		float: left;
	}
	
	#board-search .search-window {
		width: 1000px;
		min-height: 80px;
		padding: 15px 0;
		text-align: left;
	}
	
	.board-table {
		font-size: 13px;
		width: 100%;
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
	}
	
	.board-table th {
		text-align: center;
		border-top-style: solid;
		border-top-color: black;
		border-top-width: 2px;
	}
	
	.board-table .th-num {
		width: 100px;
		text-align: center;
	}
	
	table th.th-title {
		font-size: 15px;
		width: 200px;
	}
	
	table td.td-title {
		font-size: 13px;
	}
	
	table th.th-date {
		font-size: 15px;
		width: 100px;
	}
	
	table th.th-date1 {
		font-size: 15px;
		width: 65px;
	}
	
	table th.th-date2 {
		font-size: 15px;
		width: 150px;
	}
	
	table th.th-date3{
		font-size: 15px;
		width: 60px;
	}
	
	.board-table th, .board-table td {
		padding-top: 14px;
		padding-bottom: 14px;
	}
	
	.board-table tbody td {
		border-top: 1px solid #e7e7e7;
		text-align: center;
		font-size: 15px;
	}
	
	.board-table tbody th {
		font-size: 15px;
		border-top: 1px solid #e7e7e7;
		text-align: center;
	}
	
	.board-table tbody th p {
		display: none;
	}
	
	.th-list {
		text-align: center;
		margin-top: 20px;
		margin-bottom: 20px;
		padding: 10px;
		background-color: #F4A460;
		border-bottom-color: white;
		border-bottom-width: 0.2px;
		border-bottom-style: solid;
	}
	
	.td-inputInfo {
		text-align: left;
		padding-left: 20px;
		padding-top: 20px;
	}
	
	.td-infoPs {
		text-align: left;
		padding-left: 20px;
		padding-top: 5px;
		padding-bottom: 15px;
		border-bottom-color: gray;
		border-bottom-width: 0.2px;
		border-bottom-style: solid;
		font-size: 12px;
		font-weight: bold;
		color: red;
	}
	
	div.submitBtn {
		float: left;
		margin-left: 100px;
	}
	
	/* 수정 버튼 */
	#updateBtn {
		padding: 7px 15px;
		border: 1px solid #B21948;
		color: white;
		font-size: 15px;
		font-weight: bold;
		background: #b21949;
	}
	
	/* 메뉴바 */
	* {
		list-style: none;
		text-decoration: none;
		padding: 0;
		margin: 0;
		box-sizing: border-box;
	}
	
	.clearfix:after {
		content: '';
		display: block;
		clear: both;
	}
	
	div.myPageTitle {
		width: 1100px;
		margin: 0 auto;
		border: 1px solid red;
	}
	
	.innerWrap {
		width: 1000px;
		min-height: 700px;
		padding: 20px;
		float: left;
		margin-top: 10px;
		margin-left: 100px;
	}
	
	.blind {
		position: absolute;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		margin: -1px;
		width: 1px;
		height: 1px;
	}
	
	/* a 링크 : 메뉴바 */
	a:link.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:visited.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:hover.liList {
		text-decoration: underline;
		color: #B21948;
	}
	
	a:active.liList {
		text-decoration: none;
		color: #B21948;
	}
	
	table a:link.orderList {
		text-decoration: none;
		color: black;
	}
	
	table a:visited.orderList {
		text-decoration: none;
		color: black;
	}
	
	table a:hover.orderList {
		text-decoration: underline;
		color: #FC5400;
		cursor: pointer;
	}
	
	table a:active.orderList {
		text-decoration: none;
		color: #FC5400;
	}
	#btn{
		background-color: #B21948; 
		color: white;
		border: 1px solid white; 
		padding: 3px;
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
		<%-- 메뉴바 --%>
		<section>
		<div class="main">		
			<aside class="aside_left">
				<nav>
					<ul>
						<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"><a href="myPage_Main" style="text-decoration: none; color: #B21948;">나의 쇼핑</a></li>
						<li><a href="myPage_order" class="liList">주문ㆍ배송</a></li>
						<li><a href="myPage_like" class="liList">찜 목록</a></li>
						<li><a href="myPage_cart" class="liList">장바구니</a></li>
						<li><a href="myPage_review" class="liList">나의 상품후기</a></li>

						<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
						<li><a href="myPage_updateInfo" class="liList">회원정보 변경</a></li>
						<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
						<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
						<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList">배송지 관리</a></li>
						
						<!-- <li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 나의 상품후기</li> -->
					</ul>
				</nav>
			</aside>
	

		<%-- 본문 영역 --%>
		<div class="innerWrap">
			<section class="notice">
				<div class="page-title">
					<h3>
						<b>My Page</b>
					</h3>
				</div>
				<!--계정 -->
				<div class="memBasicInfo">
					<img src="<%=request.getContextPath()%>/images/profile.png" alt="프로필사진" style="width: 80px; height: 80px;">
				</div>

				<div class="memBasicInfo" style="width: 750px; text-align: left;">
					<b style="font-size: 20px;">마이페이지</b>
				</div>
			</section>

			<!-- board seach area -->
			<section class="notice">
				<div class="page-title">
					<b style="text-align: left; font-size: 20px;">&nbsp;&nbsp;주문내역</b>
					<a href="myPage_order" class="liList" style="margin-left: 780px; text-decoration-line: none;">[더보기]</a><br>
				</div>
				<!-- board list area -->
				<div id="board-list">
					<div class="container">
						<table class="board-table">
							<thead>
								<tr>
									<th scope="col" class="th-date1">주문번호</th>
									<th scope="col" class="th-title">제품명</th>
									<th scope="col" class="th-date">주문일자</th>
									<th scope="col" class="th-date3">주문수량</th>
									<th scope="col" class="th-date">송장번호</th>
									<th scope="col" class="th-date">총 주문금액</th>
									<th scope="col" class="th-date2">주문상태</th>
									<th scope="col" class="th-date3">비고</th>
								</tr>
							</thead>
							<tbody>
								<%-- 주문 테이블 --%>
								<c:if test="${!empty olist }"> <!-- 주문내역이 있을 경우 -->
									<c:forEach var="o" items="${olist}">
										<tr>
											<td>${o.order_no }</td>
											<th><a class="orderList" onclick="location='myPage_order?product_title=${o.order_product_title}'">${o.order_product_title }</a></th>
											<td>${o.order_date.substring(0,10) }</td>
											<td>${o.order_cnt }</td>
											<td>${o.order_invoice }</td>
											<td>${o.order_total }원</td>
											<td>접수완료</td>
											<td>
											<input type="button" id="btn" onclick="#" value="배송조회">&nbsp;&nbsp;&nbsp;
											</tr>
										</c:forEach>
									</c:if>
									
									<c:if test="${empty olist }"> <!-- 주문 내역이 없을 경우 -->
									<tr>
										<th colspan="7">현재 주문한 제품이 없습니다.</th>
									</tr>
									</c:if>
							</tbody>
						</table>
					</div> <!-- end container -->
				</div>
				<br><br>
				
				<!-- board list area -->
				<div id="board-list">

				</div>
				</section>
				</div>

				</div> <!--end innerWrap -->
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
		<%-- 리뷰 작성 페이지 --%>
		function openPopup_myPage_review_write() {
			var page_width = '490';
			var page_height= '900';
			
			//팝업창 가운데 띄우기
			var page_left = Math.ceil((window.screen.width - page_width)/2);
			var page_top = Math.ceil((window.screen.height - page_height)/2);
			
			  window.open("mypage/myPage_review_write", "review_write",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
		}
	</script>
</body>
</html>