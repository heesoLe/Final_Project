//관리자 회원관리페이지

//회원검색
function Member_List(){
	   var searchType =  $('#search_type').val();
	   var searchField =  $('#search_field').val();

	  var adminTab = $('#adminTab1').attr('value');
	  console.log(adminTab);
	
  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/admin_list", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"search_field" : searchField,
      	"search_type" : searchType,
		"adminTab" : adminTab
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
      var mlist = res.mlist;
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();
        var memberCountHtml = "<div align='right'>총 회원 수: " + res.member_count + "명</div>";
        $('#ajaxHead').append(memberCountHtml);

        var table_head = `
          <h3 align="center">&nbsp;회원&nbsp;관리</h3>
          <table align="center">
            <tr>
              <td align="center">
                <select name="search_type" id="search_type">
                  <option value="All" ${searchType == 'All' ? 'selected' : ''}>전체</option>
                  <option value="user_id" ${searchType == 'user_id' ? 'selected' : ''}>아이디</option>
                  <option value="user_name" ${searchType == 'user_name' ? 'selected' : ''}>이름</option>
                  <option value="user_birth" ${searchType == 'user_birth' ? 'selected' : ''}>생년월일</option>
                  <option value="user_email" ${searchType == 'user_email' ? 'selected' : ''}>이메일</option>
                  <option value="user_phone" ${searchType == 'user_phone' ? 'selected' : ''}>전화번호</option>
                </select> 
                <input id="search_field" name="search_field" size="20"> &nbsp;&nbsp;&nbsp;
                <input type="button" id="btn" name="search" value="검색" onclick="Member_List();" />
              </td>
            </tr>
          </table>
          <p>
          <p>
          `
          $('#ajaxHead').append(table_head);
          
          $('#ajaxTh').empty();
          
          var table_th = `
					<tr>
						<th width="1%" height="50">&nbsp;</th>
						<th width="5%">No</th>
						<th width="5%">아이디</th>
						<th width="7%">이름</th>
						<th width="8%">생년월일</th>
						<th width="25%">이메일</th>
						<th width="10%">전화번호</th>
						<th width="10%">가입날짜</th>
						<th width="29%">비고</th>
	
					</tr>
        `;
        // <input type="hidden" id="user_no" name="user_no" value="${mlist[i].user_no}">
        $('#ajaxTh').append(table_th);
        
		$('#ajaxTable').empty();
		
		 for(let i = 0; i < mlist.length; i++){
			 const html = `

				<tr>
				
			 <td> </td>	
  			 <td>${mlist[i].user_no}</td>
			 <td id="user_id" name="user_id">${mlist[i].user_id}</td>
			 <td id="user_name" name="user_name">${mlist[i].user_name}</td>
			 <td id="user_birth" name="user_birth">${mlist[i].user_birth}</td>
			 <td id="user_email" name="user_email">${mlist[i].user_email}</td>
			 <td id="user_phone" name="user_phone">${mlist[i].user_phone}</td>
			 <td id="join_date" name="join_date">${mlist[i].join_date.substring(0,10)}</td>
			 <td align="center">
			 <input id="btn" type="button" value="회원정보 수정" onclick="aMember_Edit(${mlist[i].user_no});" >
			 &nbsp;&nbsp;
			 <input id="btn" type="button" value="블랙리스트 등록" onclick="aMember_black(${mlist[i].user_no})" /> 
			 </td>						 
			 
			 </tr>
			 `;
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
	  }
	  }
    });//$.ajax
};

//회원정보 수정
function aMember_Edit(user_no){
	   //var user_no =  $('#user_no').val();
	
  $.ajax({
      url:"/aMember_Edit", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"user_no" : user_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
		$('#ajaxhome').empty();
		
        var table_head = `
				<input type="hidden" id="user_no" name="user_no" value="${res.user_no}">
				<table class="memList" align="center">
					<tr> 
						<th class="th-list">아&nbsp;이&nbsp;디 </th>
						<td class="td-inputInfo"> 
						<input type="text" name="user_id" id="user_id" size="70" value="${res.user_id }" readonly style="background-color: #e0e0e0;"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list">이&nbsp;름&nbsp;</th>
						<td class="td-inputInfo">
							<input type="text" name="user_name" id="user_name" value="${res.user_name}" size="70" placeholder="ex) 홍길동">
						</td>
						
					</tr>			
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list" >생&nbsp;년&nbsp;월&nbsp;일</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_birth" id="user_birth" value="${res.user_birth}" size="70" placeholder="ex) 990312">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list" >성&nbsp;별&nbsp;</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_gender" id="user_gender" value="${res.user_gender}" size="70" placeholder="ex) 남자, 여자">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr> 
						<th rowspan="4" class="th-list">주&nbsp;소</th>
						<td class="td-inputInfo">
						<input type="text" name="postCode" id="postCode" value="${res.postCode}" size="20" placeholder="우편번호"/>&nbsp;&nbsp;
						<input id="btn2" type="button" value="주소검색"/>
						</td>
					</tr>
					<tr>
						<td class="td-inputInfo">
							<input type="text" name="roadAddr" id="roadAddr" value="${res.roadAddr}"	size="70" placeholder="주소">
						</td>
					</tr>
					<tr>
						<td class="td-inputInfo"><input type="text" name="detailAddr" id="detailAddr" value="${res.detailAddr}" size="70" placeholder="상세주소"></td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
										
					<tr>
						<th class="th-list" rowspan="2" >이&nbsp;메&nbsp;일</th>
						<td class="td-inputInfo"><input type="email" name="user_email" id="user_email" value="${res.user_email}" size="70" placeholder="ex) abcdefg11@naver.com">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr>
						<th rowspan="2" class="th-list">연&nbsp;락&nbsp;처</th>
						<td class="td-inputInfo">
								<input type="text" name="user_phone" id="user_phone" size="70" value="${res.user_phone}" size="70" placeholder="ex) 01012345678">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					
					<tr>
						<th rowspan="2" class="th-list">회원 유형</th>
						<td class="td-inputInfo">
								<input type="text" name="user_state" id="user_state" size="70" value="${res.user_state}" size="70" placeholder="ex) 회원 0, 블랙리스트 1, 탈퇴회원 2" readonly style="background-color: #e0e0e0;">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs" style="color:red;">* 회원 0, 블랙리스트 1, 탈퇴회원 2</td>
					</tr>
					
				</table><br><br>
				<input id="btn" type="button" value="수정" onclick="return edit_check();" />
				&nbsp;					
				<input id="btn" type="button" value="목록보기" onclick="Member_List();" />
	
          `
          $('#ajaxHead').append(table_head);
	  }
    });//$.ajax
};


//회원정보 수정 ok
function aMember_Edit_ok(){

	
  $.ajax({
      url:"/aMember_Edit_ok", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"user_no" : $('#user_no').val()
      	, "user_name" : $('#user_name').val()
      	, "user_birth" : $('#user_birth').val()
      	, "user_gender" : $('#user_gender').val()
      	, "postCode" : $('#postCode').val()
      	, "roadAddr" : $('#roadAddr').val()
      	, "detailAddr" : $('#detailAddr').val()
      	, "user_email" : $('#user_email').val()
      	, "user_phone" : $('#user_phone').val()
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {
      	alert('회원정보 수정 성공');
		Member_List();
		//location='admin_main'
	  }
    });//$.ajax
};


//블랙리스트 등록
function aMember_black(user_no){
	   //var user_no =  $('#user_no').val();
	
  $.ajax({
      url:"/aMember_Edit", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"user_no" : user_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();

        var table_head = `
				<input type="hidden" id="user_no" name="user_no" value="${res.user_no}">
				<table class="memList" align="center">
					<tr> 
						<th class="th-list">아&nbsp;이&nbsp;디 </th>
						<td class="td-inputInfo"> 
						<input type="text" name="user_id" id="user_id" size="70" value="${res.user_id }" readonly style="background-color: #e0e0e0;"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list">이&nbsp;름&nbsp;</th>
						<td class="td-inputInfo">
							<input type="text" name="user_name" id="user_name" value="${res.user_name}" readonly  size="70" placeholder="ex) 홍길동" style="background-color: #e0e0e0;">
						</td>
						
					</tr>			
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list" >생&nbsp;년&nbsp;월&nbsp;일</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_birth" id="user_birth" value="${res.user_birth}" readonly  size="70" placeholder="ex) 990312" style="background-color: #e0e0e0;">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<tr>
						<th rowspan="2" class="th-list" >성&nbsp;별&nbsp;</th>
						<td class="td-inputInfo"> 
							<input type="text" name="user_gender" id="user_gender" value="${res.user_gender}" readonly  size="70" placeholder="ex) 남자, 여자" style="background-color: #e0e0e0;">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr> 
						<th rowspan="4" class="th-list">주&nbsp;소</th>
						<td class="td-inputInfo">
						<input type="text" name="postCode" id="postCode" value="${res.postCode}" size="20" readonly  placeholder="우편번호" style="background-color: #e0e0e0;"/>&nbsp;&nbsp;
						<input id="btn2" type="button" value="주소검색"/>
						</td>
					</tr>
					<tr>
						<td class="td-inputInfo">
							<input type="text" name="roadAddr" id="roadAddr" value="${res.roadAddr}" readonly size="70" placeholder="주소" style="background-color: #e0e0e0;">
						</td>
					</tr>
					<tr>
						<td class="td-inputInfo"><input type="text" name="detailAddr" id="detailAddr" value="${res.detailAddr}" readonly size="70" placeholder="상세주소" style="background-color: #e0e0e0;"></td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
										
					<tr>
						<th class="th-list" rowspan="2" >이&nbsp;메&nbsp;일</th>
						<td class="td-inputInfo"><input type="email" name="user_email" id="user_email" value="${res.user_email}" readonly size="70" placeholder="ex) abcdefg11@naver.com" style="background-color: #e0e0e0;">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
				
					<tr>
						<th rowspan="2" class="th-list">연&nbsp;락&nbsp;처</th>
						<td class="td-inputInfo">
								<input type="text" name="user_phone" id="user_phone" size="70" value="${res.user_phone}" size="70" readonly  placeholder="ex) 01012345678" style="background-color: #e0e0e0;">
						</td>
					</tr>
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					
					<tr>
						<th rowspan="2" class="th-list">회원 유형</th>
						<td class="td-inputInfo">
								<input type="text" name="user_state" id="user_state" size="70" value="${res.user_state}" size="70" placeholder="ex) 회원 0, 블랙리스트 1, 탈퇴회원 2" >
						</td>
					</tr>
					<tr>
						<td class="td-infoPs" style="color:red;">* 회원 0, 블랙리스트 1, 탈퇴회원 2</td>
					</tr>
					
				</table><br><br>
				<input id="btn" type="button" value="수정" onclick="return Bedit_check()" />
				&nbsp;					
				<input id="btn" type="button" value="목록보기" onclick="Member_List();" />
					
				</form> 
          `
          $('#ajaxHead').append(table_head);
	  }
    });//$.ajax
};


//블랙리스트 수정
function aMember_Black_ok(){
	
  $.ajax({
      url:"/aMember_Black_ok", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"user_no" : $('#user_no').val()
      	, "user_state" : $('#user_state').val()
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
      alert('블랙리스트 등록 성공');
		Member_List();
		//location='admin_main'
	  }
    });//$.ajax
};


	function edit_check() {
		var answer;
		answer=confirm("회원정보를 수정하시겠습니까?");
							
		if(answer == true){
			aMember_Edit_ok();
			return true;
		} else if (answer == false){
			return false;
		}
	}
	
	function Bedit_check() {
		var answer;
		answer=confirm("블랙리스트로 등록하시겠습니까?");
							
		if(answer == true){
			aMember_Black_ok();
			return true;
		} else if (answer == false){
			return false;
		}
	}