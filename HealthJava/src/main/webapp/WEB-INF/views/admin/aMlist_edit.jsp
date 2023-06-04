<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="<%=request.getContextPath()%>/js/admin.js"></script>

<title>HealthJava 관리자 회원관리 Page</title>


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
		position : relative;
		top: 105px;
		left: 50%;
	       transform: translateX( -50% );
		background-color: white;  /* 영역 보기 편하라고 배경색 지정함 : 하얀색 */
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
	#btn2{
		border-color: #b21949; 
		background-color: #b21949; 
		color: #fff;
	}
	/* 회원관리 게시판 전체 틀 */ 
	.list {
		width: 1400px;
		height: 80px;
		padding-top: 50px;
		padding-left: 50px;
		padding-right: 100px;
		font-family: 'KIMM_Bold';
	}
	/* 게시판 테두리 : table */
	.memList{
		width: 1250px;	
	    border-top: 3px solid #FC5400;
	    border-bottom: 3px solid #FC5400;
	    font-family: 'KIMM_Bold';	
	}
	.memList th {
		width: 250px;
	}
	.memList td {
		font-family: 'KIMM_Bold';
		line-height: 3;
		padding-top: 20px;
		padding-bottom: 0px;
	}
	th.th-list {
	    /*border-bottom: 2px solid #f5ad56;*/
	    font-family: 'KIMM_Bold';
	    padding-top: 20px;
		padding-bottom: 20px;
	}
	.td-infoPs {
		/*border-bottom: 2px solid #f5ad56;*/
		font-family: 'KIMM_Bold';
		padding: 10px 120px;
		text-align: left;
	}
	.td-inputInfo {
		text-align: left;
	    padding-left: 110px;
	}
	.meau {
		padding-top: 30px;
		padding-left: 800px;
		font-family: 'KIMM_Bold';
	}
	
	.meau a {
		color: white;
		text-decoration: none;
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
		border-color: #b21949;
		background-color: #b21949;
		color: #fff;
	}
	/* 페이징 처리 */
	/* 페이징 전체 틀 */
	.pagination-container {
		margin: 10px auto;
		display: flex;
		justify-content: center;
	}
	
	.pagination {
		position: relative;
	}
	/* 'PREV' 전체 틀 */
	#pagination a {
		position: relative;
		display: inline-block;
		color: #b21949; /* 글자색상 */
		text-decoration: none;
		font-size: 1.2rem;
		padding: 8px 16px 10px;
	}
	/* 'PREV' 부분 */
	#pagination a:before {
		z-index: -1;
		position: absolute;
		height: 100%;
		width: 100%;
		content: "";
		top: 0;
		left: 0;
		background-color: #FC5400;
		border-radius: 24px;
		-webkit-transform: scale(0);
		transform: scale(0);
		transition: all 0.2s;
	}
	
	#pagination a:hover, #pagination a #pagination-active {
		color: #fff;
	}
	
	#pagination a:hover:before, #pagination a #pagination-active:before {
		-webkit-transform: scale(1);
		transform: scale(1);
		background-color: #FC5400;
	}
	
	#pagination #pagination-active {
		color: #fff;
		background-color: #FC5400;
	}
	
	#pagination #pagination-active:before {
		-webkit-transform: scale(1);
		transform: scale(1);
	}
	/*'NEXT' 전체 틀 */
	#pagination-newer {
		margin-right: 50px;
	}
	
	#pagination-older {
		margin-left: 50px;
	}
	
	.boardList tr {
		border-bottom: 1px solid #b21949;
	}
	.meau {
		padding-top: 30px;
		padding-left: 800px;
		font-family: 'KIMM_Bold';
	}
	
	.meau a {
		color: white;
		text-decoration: none;
	}
	select {
		padding : 5px 5px;
	}
	
/* adminMemList.jsp UI : 회원 관리 */
/* 회원관리 게시판 전체 틀 */
.list {
	width: 1400px;
	height: 80px;
	padding-top: 50px;
	padding-left: 50px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
}
/* 게시판 테두리 */
.boardList {
	border: none;
	border-top: 2px solid #b21949;
	border-bottom: 2px solid #b21949;
	font-family: 'KIMM_Bold';
}
.boardList th {
	border-bottom: 1px solid #b21949;
}


/* admin계정 UI */

/* 관리자 메인이미지  */
.adminMainpage {
	width: 1400px;
	height: 300px;
	position: relative;
	left: 50%;
	transform: translateX(-50%);
}

.profile_img {
	width: 1400px;
	height: 200px;
	padding-left: 50px;
	padding-right: 100px;
	background-color: #b21949;
}

/*Admin Page 지정*/
.name {
	padding-top: 30px;
	padding-left: 10px;
	padding-right: 1000px;
	font-family: 'KIMM_Bold';
}

.myinfo {
	padding-left: 170px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
	color: white;
}

.myinfo_date {
	padding-left: 170px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
	color: white;
}

.meau {
	padding-top: 30px;
	padding-left: 800px;
	font-family: 'KIMM_Bold';
}

.meau a {
	color: white;
	text-decoration: none;
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
			<h1 class="name" style="color: #b21949">Admin Page</h1>
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
				
				<%-- 전체 틀 회원 수정 테이블 (list) --%>
				<div class="list">
				<h3 align="center">&nbsp;회원&nbsp;수정</h3><p>
										
				<%--회원 수정 테이블 --%>
				<c:set var="m" value="${mvo}" />
				<form method="post" id="editForm" action="member_edit_ok" >
				<input type="hidden" id="user_no" name="user_no" value="${m.user_no}">
				<table class="memList" align="center">
					<tr> <%--아이디 --%>
						<th class="th-list">아&nbsp;이&nbsp;디 </th>
						<td class="td-inputInfo"> 
						<input type="text" name="user_id" id="user_id" size="70" value="${m.user_id }" readonly style="background-color: #e0e0e0;"></td>
					</tr>

					<tr> <%-- 이름 --%>
						<th rowspan="2" class="th-list">이&nbsp;름&nbsp;</th>
						<td class="td-inputInfo">
							<input type="text" name="user_name" id="user_name" value="${m.user_name}" size="70" placeholder="ex) 홍길동">
						</td>
						
					</tr>			
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr><%-- 생년월일 --%>
						<th rowspan="2" class="th-list" >생&nbsp;년&nbsp;월&nbsp;일</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_birth" id="user_birth" value="${m.user_birth}" size="70" placeholder="ex) 990312">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr><%-- 성별--%>
						<th rowspan="2" class="th-list" >성&nbsp;별&nbsp;</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_gender" id="user_gender" value="${m.user_gender}" size="70" placeholder="ex) 남자, 여자">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr> <%--주소 --%>
						<th rowspan="4" class="th-list">주&nbsp;소</th>
						<td class="td-inputInfo">
						<%-- 우편 번호 --%>
						<input type="text" name="postCode" id="postCode" value="${m.postCode}" size="20" placeholder="우편번호"/>&nbsp;&nbsp;
						<input id="btn2" type="button" value="주소검색"/>
						</td>
					</tr>
					<tr><%-- 기본주소 --%>
						<td class="td-inputInfo">
							<input type="text" name="roadAddr" id="roadAddr" value="${m.roadAddr}"	size="70" placeholder="주소">
						</td>
					</tr>
					<tr><%-- 상세주소 --%>
						<td class="td-inputInfo"><input type="text" name="detailAddr" id="detailAddr" value="${m.detailAddr}" size="70" placeholder="상세주소"></td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
										
					<tr><%-- 이메일 --%>
						<th class="th-list" rowspan="2" >이&nbsp;메&nbsp;일</th>
						<td class="td-inputInfo"><input type="email" name="user_email" id="user_email" value="${m.user_email}" size="70" placeholder="ex) abcdefg11@naver.com">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr><%-- 연락처 --%>
						<th rowspan="2" class="th-list">연&nbsp;락&nbsp;처</th>
						<td class="td-inputInfo">
								<input type="text" name="user_phone" id="user_phone" size="70" value="${m.user_phone}" size="70" placeholder="ex) 01012345678">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					
					<tr><%-- 회원유형 --%>
						<th rowspan="2" class="th-list">회원 유형</th>
						<td class="td-inputInfo">
								<input type="text" name="user_state" id="user_state" size="70" value="${m.user_state}" size="70" placeholder="ex) 회원 0, 블랙리스트 1, 탈퇴회원 2" readonly style="background-color: #e0e0e0;">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs" style="color:red;">* 회원 0, 블랙리스트 1, 탈퇴회원 2</td>
					</tr>
					
				</table><br><br>
				<input id="btn" type="submit" value="수정" onclick="return edit_check();" />
				&nbsp;					
				<input id="btn" type="button" value="목록보기" onclick="location.href ='admin_main';" />
					
				</form> 
					<br><p>

					<script> <%-- 수정 버튼 클릭시 --%>						
						function edit_check() {
							var answer;
							var editForm = document.getElementById('editForm');
							answer=confirm("회원정보를 수정하시겠습니까?");
							
							if(answer == true){
								alert("회원수정이 완료되었습니다.");
								editForm.submit();
								location.href='admin_main';
								return true;
							} else if (answer == false){
								return false;
							}
						}
				</script>
					</div><%-- end 전체 틀 회원 수정 테이블 (list)  --%>	
				</div> <%-- end main --%>	
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