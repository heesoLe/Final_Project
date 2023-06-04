<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="../include/header.jsp"/>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/cs/css/customer_center.css">
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/header.css"> <%-- header.css --%>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/footer.css"> <%-- footer.css --%>
<script type="text/javascript" src="<%=request.getContextPath()%>/js/jquery.js"></script>
<script src="../js/cs.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 찾아오시는길</title>
</head>
<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
		</header>
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<section>
			<div class="main">
		    	<div class="wrapheaderBox">
		    		<h1>HealthJava 위치 안내</h1>
		    	</div>
		    	<div class="wraptitleBox">
		    		<p>
			    		|<br> [ HealthJava 위치 안내입니다. ] <br> |
		    		</p>
		    	</div>
		    	<div style="height:700px;">
				<div class="kakaoMap" id="map" style="margin:auto; width:1100px; height:620px;">
				</div>
				</div>
			</div>
			<script type="text/javascript" src="//dapi.kakao.com/v2/maps/sdk.js?appkey=8adefbb5f10f3767fb3c31641f4141d8"></script>
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
		<%-- 카카오맵 부분 --%>
        // 카카오 지도
        /*global kakao*/
		var mapContainer = document.getElementById('map'), // 지도를 표시할 div
		    mapOption = {
		        center: new kakao.maps.LatLng(37.4966703564534, 127.03003244234769), // 지도의 중심좌표
		        level: 4 // 지도의 확대 레벨
		    };
		
		var map = new kakao.maps.Map(mapContainer, mapOption);
		
		// 마커가 표시될 위치입니다 
		var markerPosition  = new kakao.maps.LatLng(37.4966703564534, 127.03003244234769);
		
		// 마커를 생성합니다
		var marker = new kakao.maps.Marker({
		    position: markerPosition
		});
		
		// 마커가 지도 위에 표시되도록 설정합니다
		marker.setMap(map);
		
		var iwContent = '<div style=" width:350px; height:80px; "><strong>HealthJava!</strong><br>서울특별시 강남구 강남대로84길 16 11, 12층<br><a href="https://map.kakao.com/link/map/HealthJava!!,37.4966703564534, 127.03003244234769" style="color:blue" target="_blank">큰지도보기</a> <a href="https://map.kakao.com/link/to/Puppy Home!,37.4966703564534, 127.03003244234769" style="color:blue" target="_blank">길찾기</a></div>', // 인포윈도우에 표출될 내용으로 HTML 문자열이나 document element가 가능합니다
		    iwPosition = new kakao.maps.LatLng(37.4966703564534, 127.03003244234769); //인포윈도우 표시 위치입니다
		
		// 인포윈도우를 생성합니다
		var infowindow = new kakao.maps.InfoWindow({
		    position : iwPosition,
		    content : iwContent
		});
		  
		// 마커 위에 인포윈도우를 표시합니다. 두번째 파라미터인 marker를 넣어주지 않으면 지도 위에 표시됩니다
		infowindow.open(map, marker);
	</script>
</body>
</html>