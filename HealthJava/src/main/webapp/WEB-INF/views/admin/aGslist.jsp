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

<title>HealthJava 관리자 상품목록 Page</title>


<script	src="../js/admin.js"></script>
<script>
$(document).ready(function(){
	product_search();
});
</script>


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
	/* 관리자 프로필 계정 NOTOCH */
	.adminMainpage {
		width: 1100x;
		height: 300px;
		position : relative;
		left: 50%;
	       transform: translateX( -50% );
	}
	.profile_img{
		width: 1400px;
		height: 200px;
		padding-left: 50px; 
		padding-right: 100px;
		background-color: #fc9300;
	}
	/* 상품 목록 */ 
	.product{
		width: 1400px;
		height: 80px;
		padding-top: 50px;
		padding-left: 50px; 
		padding-right: 100px;
		font-family: 'KIMM_Bold';
	} 
	/* 상품 등록 리스트 테두리 */ 
	.productList{
		width: 1250px;
		margin-left: 0px;
		margin-right: 0px;
		border-top: 2px solid #b21949;
	    border-bottom: 2px solid #b21949;	    
		font-family: 'KIMM_Bold';
	}
	.productList th {
		border-bottom: 1px solid #b21949;
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
		background-color: #b21949;
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
	}
	
	#pagination #pagination-active {
		color: #fff;
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
	.MemList {
		border: none;
		width: 1300px;
		height: 250px;
		border-top: 2px solid #b21949;
		border-bottom: 2px solid #b21949;
		font-family: 'KIMM_Bold';
	}
	
		tbody, td, tfoot, th, thead, tr {
    border-color: inherit;
    border-style: solid;
    border-width: 0;
    padding: 5px 3px;
}
	
	.MemList tr {
		border-bottom: 1px solid #b21949;
	}
	#btn {
		border-color: #b21949; 
		background-color: #b21949; 
		color: #fff;
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

/* 기본  */
/* 폰트 CSS */
@font-face {
	font-family: 'KIMM_Bold';
	src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
	font-weight: 700;
	font-style: normal;
}

/* 클리어 */
.clear {
	clear: both;
}
/* 밑의 영역부터 css시작 */
.container {
	width: 100%;
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
.pagination a {
	position: relative;
	display: inline-block;
	color: #b21949; /* 글자색상 */
	text-decoration: none;
	font-size: 1.2rem;
	padding: 8px 16px 10px;
}
/* 'PREV' 부분 */
.pagination a:before {
	z-index: -1;
	position: absolute;
	height: 100%;
	width: 100%;
	content: "";
	top: 0;
	left: 0;
	background-color: #b21949;
	border-radius: 24px;
	-webkit-transform: scale(0);
	transform: scale(0);
	transition: all 0.2s;
}

.pagination a:hover, .pagination a .pagination-active {
	color: #b21949;
}

.pagination a:hover:before, .pagination a .pagination-active:before {
	-webkit-transform: scale(1);
	transform: scale(1);
}

.pagination .pagination-active {
	color: #b21949;
}

.pagination .pagination-active:before {
	-webkit-transform: scale(1);
	transform: scale(1);
}
/*'NEXT' 전체 틀 */
.pagination-newer {
	margin-right: 50px;
}

.pagination-older {
	margin-left: 50px;
}
/* adminMemBoard.jsp UI : 고객게시판 */
/* 문의 게시판 전체 틀 */
.board {
	width: 1400px;
	height: 80px;
	padding-top: 50px;
	padding-left: 50px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
}
/* 게시판 테두리 */
.MemList {
	border: none;
	width: 1300px;
	height: 250px;
	border-top: 2px solid #b21949;
	border-bottom: 2px solid #b21949;
	font-family: 'KIMM_Bold';
}

.MemList th {
	border-bottom: 1px solid #b21949;
}
.MemList tr{
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
				
			<%-- 상품 목록 제목 + 버튼 --%>
			<div class="product">
				<h3 align="center">&nbsp;상품&nbsp;목록</h3><p>
														
				<%-- 검색 테이블 --%>
					<table align="center">
						<tr>
						<td align="center">
							<select name="search_type" id="search_type">
								<option value="All" 
								<c:if test="${search_type == 'All'}" >${'selected'}</c:if>>전체</option>
								<option value="product_title" 
								<c:if test="${search_type == 'product_title'}" >${'selected'}</c:if>>상품명</option>
								<option value="product_maker" 
								<c:if test="${search_type == 'product_maker'}" >${'selected'}</c:if>>제조사</option>
								<option value="product_type" 
								<c:if test="${search_type == 'product_type'}" >${'selected'}</c:if>>대분류</option>
								<option value="product_type2" 
								<c:if test="${search_type == 'product_type2'}" >${'selected'}</c:if>>소분류</option>
							</select>
								<input id="search_field" name="search_field" onkeyup="product_search()" size="20"> &nbsp;&nbsp;&nbsp;
								<input type="button" id="btn" name="search" onclick="product_search();" value="검색"  />
						</td>
						</tr>
					</table><p>	
								
				<div align="right">총 상품 종류 개수 : ${product_count}개</div><p>
				<%-- 상품 리스트(productList) --%>
				<table class="productList" width="1300px;">
				<thead>						
				<tr>
					<th width="50" height="50">&nbsp;</th>
					<th width="50">No</th> 
					<th width="400">상품명</th>  
					<th width="200">제조사</th>  
					<th width="300">대분류</th> 
					<th width="300">소분류</th> 
					<th width="200">가격</th>
					<th width="200">등록날짜</th> 
					<th width="100">비고</th> <%-- 수정버튼 --%>
				</tr>
				</thead>
				
				<tbody id="ajaxTable">
				
				</tbody>		
									
				</table> <%-- end productList --%>
				
				<p><br>
				<input id="btn" type="button" value="상품등록" onclick="location='product_register.shop'"/>
	
								
				</div> <%-- end product --%>
					
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
	</div>
</body>

</html>