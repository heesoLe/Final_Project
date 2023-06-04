<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="<%=request.getContextPath()%>/js/jquery.js"></script>
<script src="<%=request.getContextPath()%>/js/admin.js"></script>

<title>PuppyHome 관리자 문의게시판</title>

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
					<a href="admin_GsList">상품 목록</a> | 
					<a href="admin_GsQNAList">상품 QNA</a> | 
					<a href="admin_OrderList">주문내역</a>  
				 </div>

				<h3 class="myinfo" align="left"><b>관리자 계정</b> <br>
			</div> <%-- end profile_img : 이미지 div --%>
			</div> <%-- end adminMainpage : 관리자 계정 고정 --%>
			
			<div class="replyOk">
			<form method="post" action="csboard_replyok.shop" onsubmit="return write_check();"> <%-- 답변 히든 값 --%>
			
			<input type="hidden" name="client_ref" value="${cv.client_ref }"> <%-- 원본글과 답변글을 묶어주는 그룹 번호 역할 --%>
			<input type="hidden" name="client_step" value="${cv.client_step }"> <%-- 원본글과 답변글을 구분하는 번호값을 구분하면서 몇번째 답변글인가를 알려줌 --%>
			<input type="hidden" name="page" value="${page }"> <%-- 페이징에서 책갈피 기능때문에 쪽번호, 페이지 번호를 히든을 전달 --%>
			
			</form>
			</div> <%-- end replyOk --%>
				
			</div><%-- main 끝 --%>
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
	</div> <%-- end wrap --%>
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