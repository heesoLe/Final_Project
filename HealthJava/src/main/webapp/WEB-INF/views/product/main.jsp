<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri= "http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="<%=request.getContextPath()%>/js/orderInfo.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<title>PuppyHome 사료</title>

<script>
function checkWindowSize() {
    if ( jQuery(window).width() >= 480 ) {
        $('.truncate').succinct({
            size: 100
        }); 
    }
    else if ( jQuery(window).width() >= 320 ) {
        $('.truncate').succinct({
            size: 55
        }); 
    } 
    else {
        $('.truncate').succinct({
            size: 150
        }); 
    }   
}

jQuery(document).ready(function(){
    jQuery(window).resize(checkWindowSize);
    checkWindowSize();
});
</script>
<style type="text/css">
.menuCategory li:first-child a{
    border-bottom: 5px solid black;
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
		left: 60%;
        transform: translateX( -50% );
		
	}
	section {
		height: 1500px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / .main이랑 px 맞춰야함 */
		
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
	
	img {
	  	max-width: 100%;
	}
	.product_item{
	font-family: 'KIMM_Bold';
	}
	
.product_kind{
	font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    padding: 150px;
    min-height: 30px;
    text-align: center;
    margin: 0 0;
    
}

.menuCategory{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    margin: 0;
    padding: 0;
    display: table;
    width: 100%;
    padding-bottom: 90px;
    font-size: 0;
    line-height: 0;
    border: 0;
    position: relative;
    text-align: center;

}

.menuCategory>li {
    font: 0.75em;
    color: #353535;
    list-style: none;
    display: inline-block;
    width: 20%;
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-size: 20px;
    line-height: 1;
    vertical-align: top;
    font-family: 'KIMM_Bold';
    
    
    
    
}

.menuCategory>li>ul{
    font: 0.75em;
    color: #353535;
    list-style: none;
    font-size: 15px;
    line-height: 1;
    font-family: 'KIMM_Bold';
    display: none;
    position: absolute;
    bottom: 0;
    left: 0;
    text-align: center;
    width: 100%;
    white-space: nowrap;
    margin: 0 0 0 -20px;
    padding: 28px 0;
    z-index: 1;
}


.menuCategory>li>ul>li{
    font: 0.75em;
    color: #353535;
    font-size: 15px;
    font-family: 'KIMM_Bold';
    white-space: nowrap;
    padding: 0;
    list-style: none;
    margin: 0 0;
    line-height: 14px;
    display: inline-block;
}

.menuCategory>li>ul>li>{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    white-space: nowrap;
    list-style: none;
    text-decoration: none;
    color: #000000;
    font-size: 13px;
    line-height: 1.4;
    display: inline-block;
    background: #fff;
    border: 1px solid #000;
    border-radius: 20px;
    padding: 4px 13px;
    margin: 0 0 0 20px;
    
    
    
}

.menuCategory>li>ul>li>div{
    font: 0.75em;
    color: #353535;
    font-size: 15px;
    font-family: 'KIMM_Bold';
    white-space: nowrap;
    list-style: none;
    line-height: 14px;
    padding: 0;
    display: inline-block;
    position: relative;
    width: auto;
    height: auto;
    margin: 0;
    vertical-align: top;
}


.menuCategory>li>a{
    font: 0.75em;
    list-style: none;
    font-size: 15px;
    font-family: 'KIMM_Bold';
    text-decoration: none;
    display: block;
    padding: 0 5px;
    height: 52px;
    line-height: 49px;
    border: 1px solid #eeeeee;
    font-weight: 400;
    color: #777777;
    background: none;
    width: 100%;
    text-overflow: ellipsis;
    white-space: nowrap;
    overflow: hidden;
    box-sizing: border-box;
    text-align: center;
    position: relative;
    border-top: 1px solid #eeeeee;
}



.menuCategory>li :hover{
	border-bottom: 5px solid black;
}

.menuCategory>li>a>span{
    font: 0.75em;
    list-style: none;
    font-size: 15px;
    font-family: 'KIMM_Bold';
    line-height: 49px;
    color: #777777;
    white-space: nowrap;
    text-align: center;
    display: none !important;
    font-weight: normal;
}

.menuCategory li:first-child a{
    border-bottom: 5px solid black;
}





.function{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    padding: 0;
    overflow: hidden;
    margin: 20px 0 0;
    text-align: right;
    line-height: 38px;
    border: 0;
}

.function>p{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    text-align: right;
    line-height: 38px;
    margin: 0;
    float: left;
    padding: 0 0 0 8px;
    color: #333333;
    display: none;
}

.function>ul{
    font: 0.75em ;
    color: #353535;
    font-family: 'KIMM_Bold';
    text-align: right;
    line-height: 38px;
    padding: 0;
    display: inline;
    margin: 0 4px 0 0;
}


.function>ul>li{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    line-height: 38px;
    margin: 0;
    list-style: none;
    display: inline;
    padding: 0 0 0 10px;
    position: relative;
    background: none;
}

.function>ul>li :hover{
	border-bottom: 3px solid black;
}

.function>ul>li>a{
    font: 0.75em;
    line-height: 38px;
    list-style: none;
    text-decoration: none;
    color: #b3b3b3;
    font-size: 13px;
    font-family: 'KIMM_Bold';
}


.function>span{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    text-align: right;
    line-height: 38px;
    display: none !important;
}



.function>span>a{
    font: 0.75em;
    text-align: right;
    line-height: 38px;
    text-decoration: none;
    font-family: 'KIMM_Bold';
    display: inline-block;
    padding: 0 12px;
    color: #a28c90;
    font-size: 18px;
    border-left: 0;
}





/*맨 아래 페이지 숫자 부분 css*/

.pagenumber{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    padding: 0;
    margin: 30px 0;
    text-align: center;
    font-size: 0;
    line-height: 0;

}

.first{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    text-align: center;
    font-size: 0;
    line-height: 0;
    color: #000;
    text-decoration: none;
    display: inline-block;
    width: 28px;
    height: 28px;
    vertical-align: top;
    background: url("/SkinImg/btn_page_first.gif") no-repeat;
    
    
}

.pagenumber>a{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    text-align: center;
    font-size: 0;
    line-height: 0;
    color: #000;
    text-decoration: none;
    display: inline-block;
    width: 28px;
    height: 28px;
    vertical-align: top;
    background: url("/SkinImg/btn_page_prev.gif") no-repeat;
    
    
}

.last{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    text-align: center;
    font-size: 0;
    line-height: 0;
    color: #000;
    text-decoration: none;
    display: inline-block;
    width: 28px;
    height: 28px;
    vertical-align: top;
    background: url("/SkinImg/btn_page_last.gif") no-repeat;
    
    
}

.pagenumber>a>img{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    text-align: center;
    font-size: 0;
    line-height: 0;
    color: #000;
    margin: 0;
    padding: 0;
    border: none;
    vertical-align: top;
    display: none;/*이거 없애면 이미지 깨진 화살표 생기는데 어떻게 맞춰야하는지 모르겠음...help*/
}


.pagenumber>ol{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    text-align: center;
    margin: 0;
    padding: 0;
    display: inline-block;
    font-size: 0;
    line-height: 0;
    vertical-align: top;
}

.pagenumber>ol>li{
    font: 0.75em;
    font-family: 'KIMM_Bold';
    line-height: 0;
    padding: 0;
    list-style: none;
    display: inline-block;
    margin: 0 0 0 -1px;
    font-size: 12px;
    color: #757575;
    vertical-align: top;
    border: 0;
    margin-left: 0;
}


.contents{
    font: 0.75em;
    color: #353535;
    font-family: 'KIMM_Bold';
    margin: 0;
    float: none;
    width: 100%;
    padding: 0;

}


.product_rating {
  float: right;
  width: 100%;
  height: 20px;
  overflow: hidden;
  background: url(https://bit.ly/1B4PjyM) top left no-repeat;
  background-position: center 76%;
  margin-bottom: 5px;
  
}


  

/*여기까지 내가 추가한거*/


ul.product_list {
  display: block;
  float: left;
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 100%;
}
.product_grid a {
  text-decoration: none;
}
.product_item {
  display: inline-block;
  background: #fff;
  border: 1px solid #ccc;
  padding: 10px;
  position: relative;
  border-radius: 15px;
}

.product_image {
  position: relative;
  overflow: hidden;
  border-radius: 10px;
}
.product_image a {
  display: block;
}
.product_image img {
  display: block;
  -webkit-transition: all .35s ease-in-out;
  -moz-transition: all .35s ease-in-out;
  transition: all .35s ease-in-out;
}
.product_image img:hover {
  -o-transform: scale(1.2, 1.2);
  -moz-transform: scale(1.2, 1.2);
  -webkit-transform: scale(1.2, 1.2);
  -ms-transform: scale(1.2, 1.2);
  transform: scale(1.2, 1.2);
}
.product_image:hover .product_buttons {
  bottom: 0;
}
.product_buttons {
  position: absolute;
  bottom: -40%;
  left: 0;
  width: 100%;
  text-align: center;
  -webkit-transition: all .35s ease;
  -moz-transition: all .35s ease;
  transition: all .35s ease;
}
.product_buttons button {
  color: #fff;
  border: none;
  background: rgba(0, 0, 0, 0.5);
  font-size: 1em;
  border-radius: 50%;
  width: 40px;
  height: 40px;
}
.product_buttons .product_heart:hover {
  color: white;
  background: red;
}

.product_title {
  float: left;
  width: 100%;
  text-transform: uppercase;
}

.goods_title {
  color: black;
}

.goods_title:hover {
  color: #ea2e49;
}

.product_price a {
  color: #000;
}
.price_old {
  color: #ea2e49;
  text-decoration: line-through;
}

.price_new {
  color: black;
}

.price_new:hover {
  color: #ea2e49;
}


/*==========  Mobile First Method  ==========*/

/* Custom, iPhone Retina */ 
@media only screen and (min-width : 320px) {
  ul.product_list {
    margin: 0;
  }
  .product_item {
    width: 100%;
    margin: 0;
    overflow: hidden;
  }
  .product_sale {
    position: absolute;
    z-index: 99;
    right: -28px;
    -webkit-transform: rotate(45deg);
    -moz-transform: rotate(45deg);
    transform: rotate(45deg);
  }
  .product_sale p {
    margin: 0;
    color: #fff;
    background: #ff0000;
    padding: 3px 25px;
    box-shadow: 0 2px 8px 0 rgba(0, 0, 0, 0.4);
  }
  .product_image {
    height: 150px;
    float: left;
    width: 100px;
  }
  .product_image .product_buttons {
    display: none;
  }
  .product_title h5 {
    margin: auto;
    font-size: 1em;
    font-weight: 500;
    line-height: 1;
  }
  .product_price span {
    font-size: 1.1em;
    line-height: 1;
  }

  .product_values .product_buttons {
    position: relative;
    text-align: left;
    float: left;
    margin-top: 7px;
  }
  .product_values .product_buttons button {
    color: #252525;
    background: rgba(255, 255, 255, 1);
    font-size: 1em;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    border: 1px solid #000;
  }
}

/* Extra Small Devices, Phones */ 
@media only screen and (min-width : 480px) {
  ul.product_list {
    margin: 1%;
  }
  .product_item {
    width: 49%;
    margin: 0;
  }
  .product_image {
    height: 300px;
    float: left;
    width: 100%;
    text-align: center;
  }
  .product_image img {
    max-height: 100%;
    display: inline-block;
  }
  .product_title h5 {
    font-size: 1.1em;
    font-weight: 500;
    line-height: 1;
    padding: 10px 0 0;
    text-align: center;
}
  .product_image .product_buttons {
    display: block;
  }
  .product_price {
    float: left;
    text-align: center;
    width: 100%;
  }

  .product_values .product_buttons {
    display: none;
  }
}

@media only screen and (min-width: 678px) {
  .product_item {
    width: 32.5%;
  }
}

/* Small Devices, Tablets */
@media only screen and (min-width : 768px) {

}

/* Medium Devices, Desktops */
@media only screen and (min-width : 992px) {
  .product_item {
    width: 24.25%;
  }
}

/* Large Devices, Wide Screens */
@media only screen and (min-width : 1200px) {
  .product_item {
    width: 19.5%;
  }
}



/*==========  Non-Mobile First Method  ==========*/

/* Large Devices, Wide Screens */
@media only screen and (max-width : 1200px) {

}

/* Medium Devices, Desktops */
@media only screen and (max-width : 992px) {
  
}

/* Small Devices, Tablets */
@media only screen and (max-width : 768px) {

}

/* Extra Small Devices, Phones */ 
@media only screen and (max-width : 480px) {
  .product_title h5 {
    font-weight: bold;
  }
 .product_values {
    float: left;
    width: calc(100% - 100px);
    padding: 0 10px;
  }

  .product_image {
    height: 150px;
    float: left;
    width: 100px;
  }
  .product_image .product_buttons {
    display: none;
  }
  .product_values .product_buttons {
    position: relative;
    text-align: left;
    float: left;
    margin-top: 7px;
  }
  .product_values .product_buttons button {
    color: #252525;
    background: rgba(255, 255, 255, 1);
    font-size: 1em;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    border: 1px solid #000;
  }  
}

/* Custom, iPhone Retina */ 
@media only screen and (max-width : 320px) {
   .product_sale {
    display: none;
  }
  .product_image {
    height: auto;
    width: 100%;
  }
  .product_image .product_buttons {
    display: block;
  }
  .product_values {
    width: 100%;
    padding: 0;
    margin: 5px 0;
  }
  .product_title h5 {
    margin: auto;
    font-size: 1em;
    line-height: 1;
    font-weight: bold;
  }
  .product_values .product_buttons {
    display: none;
  }
  #footerbox {
	width: 100%;
	height: 200px;
    font-size: x-small;
    font-family: 'KIMM_Bold', sans-serif;
    background-color: rgb(241, 241, 241);
}
/* 푸터 박스 안의 틀 */
#innerbox {
    width: 1300px;
    height: 180px;
    margin: auto;
}
/* 푸터 카테고리 관련 */
#categorybox {
    height: 30px;
    float: left;
    margin: 40px 0px 15px 0px;
}
#categorybox ul {
    padding: 0;
}
#categorybox li {
    list-style: none;
    list-style-type: none;
    float: left;
    margin-right: 30px;
}
#categorybox a {
    font-size: 12.5px;
    text-decoration: none;
    color: black;
}
/* 푸터 안내글 부분 */
#infobox {
    width: 1100px;
    height: 65px;
    float: left;
    text-align: left;
}
/* 나이스페이 마크 관련 */
#checkbox {
    width: 65px;
    height: 65px;
    text-align: center;
    float: right;
    margin-right: 30px;
}
input#checkIcon {
    background-image: url(../images/nicepay.png);
    background-color: transparent;
    background-repeat: no-repeat;
    background-position: 0px 0px;
    border: none;
    cursor: pointer;
    width: 55px;
    height: 64px;
}
/* 클리어 */
.clear {
	clear: both;
}

.a {
	width:200px; 
	float:left; 
	margin: 30px 30px;
}
#bFind_wrap {
  text-align: center;
}



</style>
</head>


<body>
	<%-- 전체 영역 --%>
	
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		
			
				

					
<%-- 본문시작 --%>
					<div class="product_kind">

						<div
							class="xans-element- xans-product xans-product-headcategory title ">
							<h2>
								<span class="menuImg">
									
									
									<br>
									짐볼
								</span>
							</h2>
						</div>
					</div>

						<%-- 버튼 --%>
					<div class="product_kind_button">
							<ul class="menuCategory">
								
								<li style="display:; cursor: pointer" class="xans-element- xans-product xans-product-displaycategory selected xans-record-" data-tab="짐볼" id="default">
								전체
								
									
								</li>
								
								
								
								<li style="display:;  cursor: pointer" class="xans-element- xans-product xans-product-displaycategory selected xans-record-" data-tab="케이짐볼">
								케이짐볼
								
									
								</li>
								
								
								<li style="display:;  cursor: pointer"
									class="xans-element- xans-product xans-product-displaycategory  xans-record-" data-tab="마사지볼">마사지볼 
									
								</li>
								
								
								<li style="display:;  cursor: pointer"
									class="xans-element- xans-product xans-product-displaycategory  xans-record-" data-tab="웨이트볼">웨이트볼 
								</li>
								
								
							</ul>
						</div>
					




<div class="xans-element- xans-product xans-product-normalmenu "><!--
            $compare_page = /product/compare.html
        -->
<div class="function" id="Product_ListMenu">
            <p class="prdCount">등록 제품 : <strong>224</strong>개</p>
            <ul id="type" class="xans-element- xans-product xans-product-orderby">
<li  style="cursor: pointer" class="xans-record-" data-tab="낮은가격순">낮은가격순</li>
<li style="cursor: pointer" class="xans-record-" data-tab="높은가격순">높은가격순</li>
</ul>
</div>

</div>







<br><br>





			<%--검색 폼추가 --%>
			<div id="bFind_wrap" style="text-align: center;">
    <select name="search_type" id="search_type">
        <option value="All" <c:if test="${search_type == 'All'}">selected</c:if>>전체</option>
        <option value="product_title" <c:if test="${search_type == 'product_title'}">selected</c:if>>제품이름</option>
        <option value="product_maker" <c:if test="${search_type == 'product_maker'}">selected</c:if>>제조사</option>
    </select>
    <input id="search_field" onkeyup="search_ProductList()" name="search_field" size="14" />
    <input type="button" value="검색" onclick="search_ProductList()" />
</div>
			
			<br><br>

	<div id="product_grid2" style="text-align: center;">
  
  
  
</div>

<div id="product_grid">
  
  
  
</div>



<%--페이징 즉 쪽나누기 추가 --%>
			
		
		<section id="1">
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
	
	<script src="../../js/main.js"></script>
	<script src="../../js/like_cart.js"></script>
	<script src="../../js/qna.js"></script>
	
	
	<script>
  var priceElement = document.getElementById("formattedPrice");
  var price = parseInt(priceElement.innerText);
  var formattedPrice = (price / 1000).toLocaleString() + "원";
  priceElement.innerText = formattedPrice;
</script>
	
</body>
</html>