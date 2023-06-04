<%@ page contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="<%=request.getContextPath()%>/js/cs.js"></script>
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script>

<title>HealthJava 상품등록</title>

<style type="text/css">
@charset "UTF-8";
/* admin계정 UI */

/* 관리자 메인이미지  */
.adminMainpage {
	width: 1400px;
	height: 100px;
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
	width: 1100px;
	height: 1100px;
	border: none;
	border-top: 5px solid #b21949;
	border-bottom: 5px solid #b21949;
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
		height: auto; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / section이랑 px 맞춰야함 */
		position : relative;
		top: 105px;
		left: 50%;
        transform: translateX( -50% );
		
	}
	section {
		height: 2500px;
		; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / .main이랑 px 맞춰야함 */
		
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	
	
	/*본문 css 시작*/

	/* 관리자 프로필 계정 NOTOCH */
	#adminMainpage {
		width: 1100x;
		height: 100px;
		position : relative;
		left: 50%;
        transform: translateX( -50% );
	}
	.profile_img{
		width: 1400px;
		height: 200px;
		padding-left: 50px; 
		padding-right: 100px;
	}
	.name{ /*Admin Page 지정*/
		padding-top: 30px;
		padding-left: 10px; 
		padding-right: 1000px;
		font-family: 'KIMM_Bold';
	}
	.myinfo {		
	  	padding-left: 100px;
	  	padding-right: 100px;
	  	font-family: 'KIMM_Bold';
	 }
	.myinfo_date{
		padding-left: 100px;
	  	padding-right: 100px;
	  	font-family: 'KIMM_Bold';
	}
	.location {
		padding-top: 30px;
		padding-left: 800px;
		font-family: 'KIMM_Bold';
	}
	/* 상품 등록 전체 폼*/
	.productTitle{
		width: 1400px;
		height: 180px;
		padding-top: 100px;
		padding-left: 50px; 
		padding-right: 100px;
		font-family: 'KIMM_Bold';
	}
	.productForm{
		font-family: 'KIMM_Bold';
		width: 1100px; 
		height: 1100px;
		border:none;   
	    border-top: 5px solid #b21949;
	    border-bottom: 5px solid #b21949;
	}
	.table_div table {
		border-collapse: collapse;
	}
	.table_div table th, td {
		text-align: centen;
		font-family: 'KIMM_Bold';
		border-bottom: 1px solid black;
	}
	.input{
		font-family: 'KIMM_Bold';
	}
</style>

</head>
<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>

		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp" />
		</header>
		<section>
			<div class="main">
				<%-- main 시작 --%>
				
					<div class="adminMainpage">
						<%-- adminMainpage --%>


						<%-- admin 계정 --%>
						<h1 class="name" style="color: #b21949">Admin Page</h1>
						<div class="profile_img" align="center">
							<%-- 이미지 클릭시 관리자 메인화면으로 이동 --%>
							

							<div class="meau" align="right" style="color: white;">
								<a href="admin_main">회원 관리</a> | 
								<a href="admin_CSBoard">문의 게시판</a> | 
								<a href="admin_GsList">상품 목록</a> | 
								<a href="admin_GsQNAList">상품 QNA</a> | 
								<a href="admin_OrderList">주문내역</a>  
							 </div>

							<h3 class="myinfo" align="left">
								<b>관리자 계정</b> <br>
							</h3>
							<div class="myinfo_date" align="left">가입일 : 2023.03.15.</div>
							<br>
						</div>
						<%-- end profile_img : 이미지 div --%>
					</div>
					<%-- end adminMainpage : 관리자 계정 고정 --%>

					<%-- 상품 등록 form --%>
				 <form action="/product/add_ok" method="post" enctype="multipart/form-data">
						<div class="productTitle">
							<h3 align="center">상품&nbsp;등록</h3>
							<p>
							 
							 <br><br><br>
								<%-- 상품 등록 --%>
							<table class="productForm" align="center" >

								<tr>
									<th></th>
								</tr>
								
								<tr>
									<th>상품명</th>
									<td align="left"><input type="text" class="#"
										name="product_title" width="1000px"></td>
								</tr>
								
								<tr>
									<th></th>
								</tr>

								<tr>
									<th><b>가격</b></th>
									<td align="left"><input type="text" class="#"
										name="product_price" width="1000px">&nbsp;원</td>
								</tr>

								<tr>
									<th></th>
								</tr>

								<tr>
									<th>제조사</th>
									<td align="left"><input type="text" class="#"
										name="product_maker"></td>
								</tr>
								<p>
								<tr>
								    <th>카테고리1</th>
								    <td align="left">
								        <label>분류</label>
								        <select name="product_type" onchange="handleCategory1Change(this)">
								            <option value="">선택</option>
								            <option value="매트">매트</option>
								            <option value="짐볼">짐볼</option>
								            <option value="소도구">소도구</option>
								        </select>
								    </td>
								</tr>
								<tr>
								    <th>카테고리2</th>
								    <td align="left">
								        <label>분류</label>
								        <select name="product_type2" id="category2Select">
								            <option value="">선택</option>
								        </select>
								    </td>
								</tr>
								<p>
								<tr>
									<th></th>
								</tr>
								<%-- 이미지는 images에만 있는 이미지는 업로드 하기! --%>
								<tr>
									<th>상품<br>이미지1
									</th>
									<td align="left"><br>
									<input id="image01" type="file" name="product_cont1" onchange="fileCheck01();" />
										<div class="select_img01" style="margin: 10px;">
											<img src="" style="height: 100px; width:auto; ">
										</div> 
										<script type="text/javascript">
										$("#image01") .change(
												function() {
													if (this.files && this.files[0]) {
														var reader = new FileReader;
														reader.onload = function(data) {
															$(".select_img01 img").attr("src",data.target.result);
														}
														reader.readAsDataURL(this.files[0]);
															}
														});
										function fileCheck01() {
											var file = document
													.getElementById("image01");
											//파일 경로.
											var filePath = file.files[0].name;
											//전체경로를 \ 나눔.
											var filePathSplit = filePath
													.split('\\');
											console.log(filePath);
											$('#imagesrc01').val(filePath);
										}
										</script> <br> 
										경로 : <input id="imagesrc01" type="text" name="product_cont1" size="60" readonly="readonly"></td>
										</tr>
										<tr>
									<th>상품<br>이미지2
									</th>
									
									<td align="left">
									<input id="image02" type="file" name="product_cont2" onchange="fileCheck02();" />
										<div class="select_img02" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
										$("#image02") .change(
												function() {
													if (this.files && this.files[0]) {
														var reader = new FileReader;
														reader.onload = function(data) {
															$(".select_img02 img").attr("src",data.target.result);
														}
														reader.readAsDataURL(this.files[0]);
															}
														});
											function fileCheck02() {
												var file = document
														.getElementById("image02");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath
														.split('\\');
												console.log(filePath);
												$('#imagesrc02').val(filePath);
											}
										</script> <br>
										경로 : <input id="imagesrc02" type="text" name="product_cont2" size="60" readonly="readonly"></td>
										</tr>
										<tr>
									<th>상품<br>이미지3
									</th>
									
									<td align="left">
									<input id="image03" type="file" name="product_cont3" onchange="fileCheck03();" />
										<div class="select_img03" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
										$("#image03") .change(
												function() {
													if (this.files && this.files[0]) {
														var reader = new FileReader;
														reader.onload = function(data) {
															$(".select_img03 img").attr("src",data.target.result);
														}
														reader.readAsDataURL(this.files[0]);
															}
														});
											function fileCheck03() {
												var file = document
														.getElementById("image03");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath
														.split('\\');
												console.log(filePath);
												$('#imagesrc03').val(filePath);
											}
										</script> <br> 
										경로 : <input id="imagesrc03" type="text" name="product_cont3" size="60" readonly="readonly"></td>
										</tr>
										<tr>
									<th>상품<br>이미지4
									</th>
									<td align="left">
									<input id="image04" type="file" name="product_cont4" onchange="fileCheck04();" />
										<div class="select_img04" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> 
										<script type="text/javascript">
										$("#image04") .change(
												function() {
													if (this.files && this.files[0]) {
														var reader = new FileReader;
														reader.onload = function(data) {
															$(".select_img04 img").attr("src",data.target.result);
														}
														reader.readAsDataURL(this.files[0]);
															}
														});
											function fileCheck04() {
												var file = document
														.getElementById("image04");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath
														.split('\\');
												console.log(filePath);
												$('#imagesrc04').val(filePath);
											}
										</script> <br> 
										경로 : <input id="imagesrc04" type="text" name="product_cont4" size="60" readonly="readonly"></td>
										</tr>
								<tr>
									<th>상세페이지<br>이미지01
									</th>
									<td align="left"><input id="image05" type="file"
										name="product_cont5" onchange="fileCheck05();" />
										<div class="select_img05" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
											$("#image05").change(function() {
												if (this.files&& this.files[0]) {
													var reader = new FileReader;
													reader.onload = function(data) {
														$(".select_img05 img").attr("src",data.target.result) ;
													}
													reader.readAsDataURL(this.files[0]);
													}
												});
											function fileCheck05() {
												var file = document.getElementById("image05");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath.split('\\');
												console.log(filePath);
												$('#imagesrc05').val(filePath);
											}
										</script><br> 경로 : <input id="imagesrc05" type="text"
										name="product_cont5" size="60" readonly="readonly"></td>
								</tr>
								<tr>
									<th>상세페이지<br>이미지02
									</th>
									<td align="left"><input id="image06" type="file"
										name="product_cont6" onchange="fileCheck06();" />
										<div class="select_img06" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
											$("#image06").change(function() {
												if (this.files&& this.files[0]) {
													var reader = new FileReader;
													reader.onload = function(data) {
														$(".select_img06 img").attr("src",data.target.result) ;
														}
													reader.readAsDataURL(this.files[0]);
													}
												});
											function fileCheck06() {
												var file = document.getElementById("image06");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath.split('\\');
												console.log(filePath);
												$('#imagesrc06').val(filePath);
											}
										</script> <br> 경로 : <input id="imagesrc06" type="text"	name="product_cont6" size="60" readonly="readonly"></td>
								</tr>
								<tr>
									<th>상세페이지<br>이미지03
									</th>
									<td align="left"><input id="image07" type="file"
										name="product_cont7" onchange="fileCheck07();" />
										<div class="select_img07" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
											$("#image07").change(function() {
												if (this.files&& this.files[0]) {
													var reader = new FileReader;
													reader.onload = function(data) {
														$(".select_img07 img").attr("src",data.target.result) ;
														}
													reader.readAsDataURL(this.files[0]);
													}
												});
											function fileCheck07() {
												var file = document.getElementById("image07");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath.split('\\');
												console.log(filePath);
												$('#imagesrc07').val(filePath);
											}
										</script> <br> 경로 : <input id="imagesrc07" type="text"	name="product_cont7" size="60" readonly="readonly"></td>
								</tr>
								<tr>
									<th>상세페이지<br>이미지04
									</th>
									<td align="left"><input id="image08" type="file"
										name="product_cont8" onchange="fileCheck08();" />
										<div class="select_img08" style="margin: 10px;">
											<img src="" style="height: 100px; width: auto;">
										</div> <script type="text/javascript">
											$("#image08").change(function() {
												if (this.files&& this.files[0]) {
													var reader = new FileReader;
													reader.onload = function(data) {
														$(".select_img08 img").attr("src",data.target.result) ;
														}
													reader.readAsDataURL(this.files[0]);
													}
												});
											function fileCheck08() {
												var file = document.getElementById("image08");
												//파일 경로.
												var filePath = file.files[0].name;
												//전체경로를 \ 나눔.
												var filePathSplit = filePath.split('\\');
												console.log(filePath);
												$('#imagesrc08').val(filePath);
											}
										</script> <br> 경로 : <input id="imagesrc08" type="text"	name="product_cont8" size="60" readonly="readonly"></td>
								</tr>
							</table>
							<p>
							<p>

								<input type="submit" value="등록" /> <input type="button"
									value="취소" onclick="goBack()" />
						</div>
						
					<%-- end product--%></form>
			</div>
			<%-- adminMainpage 끝--%>

	<%-- top버튼 삭제 X --%>
	<div id="topBtn">
		<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
	</div>
	</section>


	<%-- 푸터 영역 --%>
	
	<footer>
		<jsp:include page="../include/footer.jsp"/>
	</footer>

	</div>
	<%-- end main --%>



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
	<script>
    const category2Select = document.getElementById('category2Select');
    
    function handleCategory1Change(selectElement) {
        const selectedCategory1 = selectElement.value;
        clearOptions(category2Select);
        
        // 선택된 카테고리1에 따라 해당하는 옵션만 추가
        if (selectedCategory1 === '매트') {
            addOption(category2Select, '기본매트');
            addOption(category2Select, '고급매트');
            addOption(category2Select, '전문가용매트');
        } else if (selectedCategory1 === '짐볼') {
            addOption(category2Select, '케이짐볼');
            addOption(category2Select, '마사지볼');
            addOption(category2Select, '웨이트볼');
        } else if (selectedCategory1 === '소도구') {
            addOption(category2Select, '탄력밴드');
            addOption(category2Select, '매트타월');
            addOption(category2Select, '요가블럭');
        }
    }
    
    function addOption(selectElement, value) {
        const option = document.createElement('option');
        option.value = value;
        option.text = value;
        selectElement.appendChild(option);
    }
    
    function clearOptions(selectElement) {
        while (selectElement.options.length > 0) {
            selectElement.remove(0);
        }
        
        // 기본 선택 옵션 추가
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.text = '선택';
        selectElement.appendChild(defaultOption);
    }
</script>
<script>
  function goBack() {
    history.back();
  }
</script>
</body>
</html>