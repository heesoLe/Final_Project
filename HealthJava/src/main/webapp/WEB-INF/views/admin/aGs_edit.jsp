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

<title>HealthJava 상품 수정</title>

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
.productTitle {
	width: 1400px;
	height: 180px;
	padding-top: 100px;
	padding-left: 50px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
}
.productForm {
	font-family: 'KIMM_Bold';
	width: 1300px;
	height: 1100px;
	border: none;
	border-top: 5px solid #FC5400;
	border-bottom: 5px solid #FC5400;
}
.productForm tr {
	padding-top: 10px;
	padding-bottom: 10px;
}

.table_div table {
	border-collapse: collapse;
}
.productForm th, td {
	text-align: centen;
	font-family: 'KIMM_Bold';
}
.input {
	font-family: 'KIMM_Bold';
}
#btn {
	border-color: #FC5400; 
	background-color: #FC5400; 
	color: #fff;
} 

.cont {
	width: 1200px;
}
</style>

<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<section>
			<div class="main"> <%-- main 시작 --%>
				<div class="adminMainpage"><%-- adminMainpage --%>
				
						<%-- admin 계정 --%>
						<h1 class="name" style="color: #b21949">Admin Page</h1>
						 
						 <div class="profile_img" align="center">
						 <a href="admin_main">
						 <img width="150px" height="190px" align="left" alt="adminImage" src="<%=request.getContextPath() %>/images/admin.png">
						 </a>
						 
				<div class="meau" align="right" style="color: white;">
					<a href="admin_main">회원 관리</a> | 
					<a href="admin_CSBoard">문의 게시판</a> | 
					<a href="admin_GsList">상품 목록</a> | 
					<a href="admin_GsQNAList">상품 QNA</a> | 
					<a href="admin_OrderList">주문내역</a>  
				 </div>
						 
						  <h3 class="myinfo" align="left"><b>관리자 계정</b> <br></h3>
						  </div> <%-- end profile_img --%>
					
				<%-- 상품 수정 form --%>
				<form method="post" action="gsModifyOK.shop">
				<input type="hidden" name="product_no" value="${pvo.product_no}" >
				
				<div class="productTitle">
					<h3 align="center">상품&nbsp;수정</h3><p>					
					
					<%-- 상품 수정 --%>
					<table class="productForm" align="center" >					
						<tr><th></th></tr>						
						<tr>
							<th>상품명</th>
							<td align="left"><input type="text" class="#" name="product_title" value="${pvo.product_title }"></td>
						</tr> <p>						
						<tr><th></th></tr>						
						<tr>
							<th><b>가격</b></th>
							<td align="left"><input type="text"  class="#" name="product_price" value="${pvo.product_price }" width="1000px"/></td>
						</tr>
						
						<tr><th></th></tr>
						
						<tr>
							<th>제조사</th>
							<td align="left"><input type="text" value="${pvo.product_maker }" class="#" name="product_maker"></td>
						</tr> <p>
										 						
						<tr>
							<th>카테고리</th>
								
							<td align="left"> <label>분류</label>
								<select name="product_type">
									<option value="${pvo.product_type}">${pvo.product_type}</option>
									<optgroup label="사료" id="feed" >
										<option value="퍼피">퍼피</option>
										<option value="어덜트">어덜트</option>
										<option value="시니어">시니어</option> </optgroup>
									<optgroup label="간식" id="gansik" value="gansik">
										<option value="껌간식">껌간식</option>
										<option value="일반간식">일반간식</option> </optgroup>
									<optgroup label="영양제" id="medicine" value="medicine">
										<option value="유산균">유산균</option>
										<option value="오메가3">오메가3</option></optgroup>
								</select>		
						</td></tr> <p>
						
						<tr><th></th></tr>
						<tr> 
							<th>메인<br>이미지</th>
							<td align="left">
							<input id="image01" type="file" name="file" onchange="fileCheck01();" />
							<div class="select_img01" style="margin: 10px;"> 
								<img src="<%=request.getContextPath()%>/images/${product_cont1}" alt="image" style="height: 300px; width: auto;"> 
							</div>
							
							<script type="text/javascript">
							$("#image01").change(function() {
								if( this.files && this.files[0]) {
									var reader = new FileReader;
									reader.onload = function(data) {
										$(".select_img01 img").attr("src", data.target.result);
									}
									reader.readAsDataURL(this.files[0]);
								}							
							});
							function fileCheck01() {
								var file = document.getElementById("image01");
								//파일 경로.
								var filePath = file.files[0].name;
								//전체경로를 \ 나눔.
								var filePathSplit = filePath.split('\\');
								console.log(filePath);
								$('#imagesrc01').val(filePath);
							}
							</script>
							경로 : <input id="imagesrc01" type="text" name="product_cont1" size="60" value="${product_cont1}" readonly="readonly">
							</td>
						</tr>
						
						<tr>
							<th>상세페이지<br>이미지01</th>
							<td align="left">
							<input id="image02" type="file" name="file" onchange="fileCheck02();" />
							<div class="select_img02" style="margin: 10px;"> 
							<img src="<%=request.getContextPath()%>/images/${product_cont2}" alt="image" style="height: 300px; width: auto;"> 
							</div>
							
							<script type="text/javascript">
							$("#image02").change(function() {
								if( this.files && this.files[0]) {
									var reader = new FileReader;
									reader.onload = function(data) {
										$(".select_img02 img").attr("src", data.target.result);
									}
									reader.readAsDataURL(this.files[0]);
								}							
							});
							function fileCheck02() {
								var file = document.getElementById("image02");
								//파일 경로.
								var filePath = file.files[0].name;
								//전체경로를 \ 나눔.
								var filePathSplit = filePath.split('\\');
								console.log(filePath);
								$('#imagesrc02').val(filePath);
							}
							</script>
							경로 : <input id="imagesrc02" type="text" name="product_cont2" size="60" value="${product_cont2}" readonly="readonly">
							</td>
						</tr>
						
						<tr>
							<th>상세페이지<br>이미지02</th>
							<td align="left">
							<input id="image03" type="file" name="file" onchange="fileCheck03();" />
							<div class="select_img03" style="margin: 10px;"> 
							<img src="<%=request.getContextPath()%>/images/${product_cont3}" alt="image" style="height: 300px; width: auto;"> 
							</div>
							
							<script type="text/javascript">
							$("#image03").change(function() {
								if( this.files && this.files[0]) {
									var reader = new FileReader;
									reader.onload = function(data) {
										$(".select_img03 img").attr("src", data.target.result);
									}
									reader.readAsDataURL(this.files[0]);
								}							
							});
							function fileCheck03() {
								var file = document.getElementById("image03");
								//파일 경로.
								var filePath = file.files[0].name;
								//전체경로를 \ 나눔.
								var filePathSplit = filePath.split('\\');
								console.log(filePath);
								$('#imagesrc03').val(filePath);
							}
							</script>
							경로 : <input id="imagesrc03" type="text" name="product_cont3" value="${product_cont3 }" size="60" readonly="readonly">
							</td>
						
					</table> <p><p>
					
					<input id="btn" type="submit" value="수정"/>
					<input id="btn" type="button" value="삭제" onclick="location.href='gsDelOK.shop?product_no=${po.product_no}'" />
					<input id="btn" type="reset" value="취소" onclick="location='gslist.shop'" />
				
				</div>
				</form> <%--end product--%>
					
				</div><%-- adminMainpage 끝--%>
			</div> <%-- end main --%>
			
			<%-- top버튼 삭제 X --%>
			<div id="topBtn">
				<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
			</div>
		</section>
	<%-- 푸터 영역 --%>
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