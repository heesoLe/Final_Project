<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script type="text/javascript" src = "./js/jquery.js"></script>
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script src="./js/updateInfo.js"></script>
<script src="./js/post2.js"></script>

<script src="${pageContext.request.contextPath}/js/addr.js"></script>

<title>HealthJava 마이페이지</title>

<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/header.css"> <%-- header.css --%>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/footer.css"> <%-- footer.css --%>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/fontium/css/fontium.css"/>

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
		font-family: 'KIMM_Bold', sans-serif;
	}
	
	html {
		height: 100%;
	}
	
	body {
		margin: 0px;
		min-height: 100%;
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
		width: 1600px;
		height: auto;
		position: relative;
		top: 105px;
		left: 50%;
		transform: translateX(-50%);
	}
	
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}

	/*MyPage CSS*/
	table {
		border-collapse: collapse;
		border-spacing: 0;
	}
	section.notice {
		width: 1000px;
		min-height: 200px;
	}
	
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
	
	li{
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
	
	div.submitBtn{
		float: left;
		margin-left: 100px;
	}
	
	/* 배송지 수정 버튼 */
	#updateBtn{
	    padding: 20px 80px;
	    background-color: #B21948;
	    border: 1px solid white;
	    color: white;
	    font-size: 20px;
	    font-weight: bold;
	}	
	/* 취소 버튼 */
	#resetBtn{
	    padding: 20px 120px;
	    background-color: white;
	    border: 2px solid #B21948;
	    font-size: 20px;
	    font-weight: bold;
	    color: #B21948;
	}
	
	/* reset */
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
	
	div.container {
		width: 1000px;
		margin: 20px 0px;
	}
	
	.innerWrap {
		width: 1000px;
		min-height: 700px;
		padding: 20px;
		float: left;
		margin-top: 25px;
		margin-left: 50px;
	}
	
	.blind {
		position: absolute;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		margin: -1px;
		width: 1px;
		height: 1px;
	}
	
	.clear {
		clear: both; /*float 속성을 제거함으로써 잘못 된 ui 적용을 막아줌 */
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
	
	a:hover.liList{
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
	
	table a:hover.orderList{
		text-decoration: underline;
		color: #FC5400;
		cursor: pointer;
	}
	
	table a:active.orderList {
		text-decoration: none;
		color: #FC5400;
	}
	.tr{
		background-color: #B21948; 
		color: white; 
	}
	.th-mlist {
		padding: 10px;
		border-color: inherit;
    	border-style: solid;
    	border-width: 0;
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
         <jsp:include page="../include/header.jsp"/>
      </header>
      <%-- 메뉴바 --%>
		<section>
			<div class="main">
				<aside class="aside_left">
					<nav>
						<ul>
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"><a href="myPage_Main" style="text-decoration: none; color: black;">나의 쇼핑</a></li>
							<li><a href="myPage_order" class="liList">주문ㆍ배송</a></li>
							<li><a href="myPage_like" class="liList">찜 목록</a></li>
							<li><a href="myPage_cart" class="liList">장바구니</a></li>
							<li><a href="myPage_review" class="liList">나의 상품후기</a></li>
	
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
							<li><a href="myPage_updateInfo" class="liList">회원정보 변경</a></li>
							<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
							<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList" style="color: #B21948;">배송지 관리</a></li>
							
							<!-- <li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 나의 상품후기</li> -->
						</ul>
					</nav>
				</aside>
			
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<div class="innerWrap">
		<section class="notice">
			<!-- board list area -->
			<div class="page-title">
			<b style="text-align: left; font-size: 20px; margin-left:50px;">배송지 관리</b><br>
			</div>
			<!-- 배송지 리스트 : 기본/추가 -->
			<table class="mlist" style="margin-left: 50px; margin-top: 20px; width:1000px; padding: 0px 10px; text-align: left;">
			 <tr class="tr">
				<th class="th-mlist">배송지 이름</th> 
				<th>우편번호</th> 
				<th>주소</th> 
				<th>상세 주소</th> 
				<th>비고</th>
			</tr>
			 <c:if test="${!empty mlist}">
				<c:forEach var="m" items="${mlist }">
				<tr>
					<th class="th-mlist">기본주소 </th> 
					<th>${m.postCode }</th> 
					<th>${m.roadAddr }</th> 
					<th>${m.detailAddr }</th> 
					<th>
						<input type="button" value="수정" id="btn" onclick="location='myPage_updateInfo'">
					</th>
				</tr>
			</c:forEach >
			<c:forEach var="a" items="${alist }">
				<tr>
					<th class="th-mlist">${a.addr_name } </th> 
					<th>${a.postCode }</th> 
					<th>${a.roadAddr }</th> 
					<th>${a.detailAddr }</th>
					<th>
						<input type="button" id="btn" value="수정" onclick="location='addr_edit?addr_no=${a.addr_no}'">
						<input type="button" id="btn" value="삭제" onclick="location='addr_del?addr_no=${a.addr_no}'">
					</th>
				</tr>
			</c:forEach >
			</c:if>
			</table>			
				<div class="submitBtn" style="margin-left: 450px; margin-top: 50px;">
					<input type="submit" id="updateBtn" value="배송지 추가" onclick="location='addr_add'">
				</div>
			</section>
			</div>
		</div>	
		
        <%-- top버튼 삭제 X --%>
         <div id="topBtn">
            <span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
         </div>
		<div class="clear"></div>
		<%-- 푸터 영역 --%>
		</section>
		<footer>
			<!-- footer -->
			<jsp:include page="../include/footer.jsp"/>
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