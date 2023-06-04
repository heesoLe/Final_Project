-- 멤버 테이블
CREATE TABLE tbl_member(
    user_no number(38)  PRIMARY KEY -- 회원 수(unique)
    , user_id varchar2(100) unique -- 회원 아이디
    , user_pwd varchar2(100) -- 회원 비밀번호
    , user_name varchar2(100) -- 회원 이름
    , user_birth varchar2(100) -- 회원 생년월일
    , user_gender varchar2(50) -- 회원 성별
    , postcode varchar2(100) -- 회원 우편번호
    , roadAddr varchar2(100) -- 회원 도로명 주소
    , detailAddr varchar2(100) -- 회원 상세 주소
    , user_email varchar2(100) unique -- 회원 이메일
    , user_phone varchar2(100) -- 회원 휴대폰번호
    , user_state number(38) default 0 -- 회원 0, 블랙리스트 1, 탈퇴회원 2, 카카오 회원 3, 비회원 4
    , join_date date -- 가입 날짜(sysdate)
    , del_date date -- 탈퇴 날짜(sysdate)
    , del_cont varchar2(2000) -- 탈퇴사유
    , mail_key varchar2(100) --메일 인증키
    , mail_auth number(38) --1 이면 메일인증 0 이면 인증 X
);

commit;
select * from tbl_member;
-- 멤버 시퀀스
create sequence user_no_seq
    start with 1
    increment by 1
    nocache;

-- 상품 테이블
CREATE TABLE tbl_product(
    product_no   number(38) primary key , -- 상품 글 번호
    product_title varchar2(100) unique NOT NULL ,-- 상품 명
    product_price varchar2(4000) NOT NULL , -- 상품 가격
    product_maker varchar2(100) NOT NULL , -- 제조사
    product_type varchar2(100) NOT NULL ,-- 분류1
    product_type2 varchar2(100) NOT NULL ,-- 분류2
    product_cont1 varchar2(4000) NOT NULL , -- 상품사진
    product_cont2 varchar2(4000) , -- 상품사진
    product_cont3 varchar2(4000) , -- 상품사진
    product_cont4 varchar2(4000) , -- 상품사진
    product_cont5 varchar2(4000) NOT NULL , -- 상품내용사진
    product_cont6 varchar2(4000) , -- 상품내용사진
    product_cont7 varchar2(4000) ,-- 상품내용사진
    product_cont8 varchar2(4000) ,  -- 상품내용사진
    product_score varchar2(100) , -- 상품 평점 ( 리뷰 평균값 가져옴 )
    product_count varchar2(1000) , -- 상품 재고
    product_date date -- 상품 등록 날짜(sysdate)
);

   
-- 상품 시퀀스 
create sequence product_no_seq
    start with 1 --1부터 시작
    increment by 1 --1씩 증가옵션
    nocache;

-- 상품 후기 테이블
create table tbl_reviews (
    re_no NUMBER PRIMARY KEY , -- 후기 no
    re_pro_no VARCHAR2(10) , --제품no : F
    re_mem_id VARCHAR2(100) , -- 회원 아이디 
    re_title VARCHAR2(100) , -- 리뷰 제목
    re_content VARCHAR2(4000) ,  --리뷰 내용
    re_image1 VARCHAR2(4000)  , --사진 등록1
    re_image2 VARCHAR2(4000)  , -- 사진등록2
    re_image3 VARCHAR2(4000)  , -- 사진등록3
    re_star NUMBER(38) , --별점score
    re_date DATE --등록일
);

-- 상품 후기 시퀀스
create sequence re_no_seq
    start with 1
    increment by 1
    nocache;

-- 장바구니 테이블
create table tbl_cart (
   cart_no NUMBER PRIMARY KEY , -- 장바구니 no
   cart_mem_id VARCHAR(100) , -- 회원 아이디 , 비회원 아이디 :랜덤값 
   cart_pro_no VARCHAR(100) , -- 제품 고유번호 : F상품no
   cart_cnt  NUMBER(38)  -- 구매 수량
);

-- 장바구니 시퀀스
create sequence cart_no_seq
    start with 1
    increment by 1
    nocache;

--  찜 목록 테이블 
create table tbl_like (
    like_no NUMBER PRIMARY KEY , -- 찜 no
    like_mem_id VARCHAR(100) , -- 회원ID : F
    like_pro_no VARCHAR(100)  -- 제품 고유번호 : F상풍no
);

-- 찜목록 시퀀스
create sequence like_no_seq
    start with 1
    increment by 1
    nocache;

-- 주문내역 테이블
CREATE TABLE tbl_order (
    order_no NUMBER(38) PRIMARY KEY, -- 주문번호
    order_product_title VARCHAR2(100) , -- 상품명
    order_date DATE,
    order_cnt NUMBER, -- 수량
    order_invoice VARCHAR2(100), -- 배송준비 완료시 : 송장번호 10자리 
    order_total NUMBER(38) , -- 총 금액
    user_id VARCHAR2(100)  REFERENCES tbl_member(user_id) -- 회원아이디
);

ALTER TABLE tbl_order ADD user_id VARCHAR2(100) REFERENCES tbl_member(user_id);

commit;
-- drop table tbl_order;

alter table tbl_order drop CONSTRAINT order_product_title;

select * from tbl_order;

-- 주문내역(주문 목록) 시퀀스 
create sequence order_no_seq
    start with 1 --1부터 시작
    increment by 1 --1씩 증가옵션
    nocache;

-- 주문상세내역 테이블
create table tbl_order_detail (
    order_detail_no NUMBER PRIMARY KEY , -- 주문 no
    order_no NUMBER(38) REFERENCES tbl_order(order_no)  , -- 주문내역 no
    order_detail_mid VARCHAR2(100) REFERENCES tbl_member(user_id) , --회원 아이디
    order_detail_fno NUMBER(38)  REFERENCES tbl_product(product_no) , -- 상품번호
    order_detail_cnt VARCHAR2(100) -- 제품 수량
);

-- drop table tbl_order_detail;

-- 주문상세내역 시퀀스 생성 
create sequence order_detail_no_seq
    start with 1
    increment by 1
    nocache;

-- 배송지 테이블 
create table tbl_addr (
    addr_no NUMBER primary key, -- 주소 no 
    user_id VARCHAR2(100) , --회원 id
    postCode varchar2(100) , -- 회원 우편번호
    roadAddr varchar2(100) ,-- 회원 도로명 주소
    detailAddr varchar2(100) , -- 회원 상세 주소
    addr_name varchar2(100) -- 배송지 별명
);

-- 배송지 시퀀스 생성
create sequence addr_no_seq
    start with 1
    increment by 1
    nocache;

-- 1대1문의 테이블
CREATE TABLE tbl_client (
   client_no number(38) primary key -- 고객 문의 글 번호
    , client_title varchar2(100) NOT NULL -- 고객 문의 글 제목
    , contact_password varchar2(100) not null
    , client_cont varchar2(4000) NOT NULL -- 고객 문의 글 내용
    , client_cont_reply varchar2(4000) default ' ' -- 고객 문의 글 답변 내용
    , client_category varchar2(50) NOT NULL -- 회원정보, 상품확인, 주문/결제, 배송, 교환/취소/반품, 서비스
    , client_date date -- 고객 문의 글 작성 날짜(sysdate)
    , user_id varchar2(100) not null -- 회원아이디(fk)
    ,CONSTRAINT tbl_client_user_id_fk foreign key(user_id) REFERENCES tbl_member(user_id)
);

-- 1대1문의 시퀀스
create sequence client_no_seq
    start with 1
    increment by 1
    nocache;

-- 자주 묻는 질문 테이블
create table tbl_faq(
    faq_no number(38) primary key
    ,faq_category varchar2(100) not null
    ,faq_title varchar2(1000) not null
    ,faq_cont varchar2(4000) not null
);    

-- 자주 묻는 질문 시퀀스
create sequence faq_no_seq
    start with 1
    increment by 1
    nocache;

-- 공지사항 테이블
create table tbl_notice(
  notice_no number(38) primary key
  , notice_title varchar2(1000) NOT NULL 
  , notice_cont varchar2(4000) NOT NULL
  , notice_date date
);

-- 공지사항 시퀀스
create sequence notice_no_seq
    start with 1
    increment by 1
    nocache;

-- 상품 QNA 테이블
create table tbl_product_qna (
  qna_no NUMBER PRIMARY KEY 
  , qna_product_no NUMBER(38) REFERENCES tbl_product(product_no) --상품 no
  , qna_mem_id VARCHAR2(100) REFERENCES tbl_member(user_id) --유저 id
  , qna_title VARCHAR2(100) --문의 제목
  , qna_content VARCHAR2(100) --문의 내용
  , qna_reply VARCHAR2(100)  --답변
  , qna_date date -- 고객 문의 글 작성 날짜(sysdate)
);    

--drop table tbl_product_qna;

-- 상품 QNA 시퀀스
create sequence qna_no_seq
    start with 1
    increment by 1
    nocache;

-- 채팅방 테이블
create table test_chatroom(
    roomId varchar2(500)
    , name varchar2(500)
);

-- 채팅 메세지 테이블
create table test_chatmessage(
    roomId varchar2(50)
    , writer varchar2(50)
    , message varchar2(4000)
);


-- 더미 데이터
-----------------------------------------------------------------------------------------------
/*공지사항 더미데이터*/

insert into tbl_notice values
(notice_no_seq.nextval, '2023년 3월 카드혜택 안내', 
'삼성카드 : 5% 청구할인, 5% 포인트 적립
 농협카드 : 최고 30만원 캐시백(300만원 이상 10만원, 500만원 이상 20만원, 700만원 이상 30만원)
 우리카드 : 최고 24개월 무이자', '2023-03-01');
 
 insert into tbl_notice values
(notice_no_seq.nextval, '3월 출석체크 이벤트 안내', 
'헬스자바 고객님들께 3월 출석체크 일수를 기준으로 할인 쿠폰을 드립니다.
 10일 이상 : 5% 할인쿠폰 / 20일 이상 : 10% 할인쿠폰 / 25일 이상 : 15% 할인쿠폰', '2023-03-01');
 
insert into tbl_notice values
(notice_no_seq.nextval, '2023년 4월 카드혜택 안내', 
'삼성카드 : 5% 청구할인, 10% 포인트 적립
 농협카드 : 최고 20만원 캐시백(300만원 이상 10만원, 500만원 이상 20만원)
 우리카드 : 최고 12개월 무이자', '2023-04-01');
 
 insert into tbl_notice values
(notice_no_seq.nextval, '4월 출석체크 이벤트 안내', 
'헬스자바 고객님들께 4월 출석체크 일수를 기준으로 할인 쿠폰을 드립니다.
 10일 이상 : 5% 할인쿠폰 / 20일 이상 : 10% 할인쿠폰 / 25일 이상 : 15% 할인쿠폰', '2023-04-01');

insert into tbl_notice values
(notice_no_seq.nextval, '2023년 5월 카드혜택 안내', 
'삼성카드 : 10% 청구할인, 5% 포인트 적립
 농협카드 : 최고 20만원 캐시백(300만원 이상 10만원, 500만원 이상 20만원)
 우리카드 : 최고 36개월 무이자', '2023-05-01');
 
 insert into tbl_notice values
(notice_no_seq.nextval, '5월 출석체크 이벤트 안내', 
'헬스자바 고객님들께 5월 출석체크 일수를 기준으로 할인 쿠폰을 드립니다.
 10일 이상 : 5% 할인쿠폰 / 20일 이상 : 10% 할인쿠폰 / 25일 이상 : 15% 할인쿠폰', '2023-05-01');

insert into tbl_notice values
(notice_no_seq.nextval, '2023년 6월 카드혜택 안내', 
'삼성카드 : 10% 청구할인, 5% 포인트 적립
 농협카드 : 최고 30만원 캐시백(200만원 이상 3만원, 300만원 이상 5만원)
 우리카드 : 최고 36개월 무이자', '2023-06-01');
 
 insert into tbl_notice values
(notice_no_seq.nextval, '6월 출석체크 이벤트 안내', 
'헬스자바 고객님들께 6월 출석체크 일수를 기준으로 할인 쿠폰을 드립니다.
 10일 이상 : 5% 할인쿠폰 / 20일 이상 : 10% 할인쿠폰 / 25일 이상 : 15% 할인쿠폰', '2023-06-01');

insert into tbl_notice values(notice_no_seq.nextval, '개인정보 처리방침 개정안내', '제 4조(개인정보처리의 위탁항목)에서 수탁자와 위탁업무 내용이 추가됩니다. 
자세한 사항은 추후 공지될 예정입니다', sysdate);

insert into tbl_notice values(notice_no_seq.nextval, '쇼핑몰 이용약관 일부 개정 안내', '제 2조(정의), 제 4조(서비스의 제공 및 변경), 제23조 2(통신판매중개서비스) 의 내용이 추가될 예정입니다.', sysdate);

insert into tbl_notice values(notice_no_seq.nextval, '헬스자바 사칭 피싱사이트 주의 안내', '헬스자바를 찾아주시는 고객님들께 안내말씀 드립니다. 
최근 헬스자바 피싱사이트에 관한 피해가 늘고 있습니다. 
공식 사이트 주소를 잘 확인하시어 피해없으시길 바랍니다.', sysdate);

insert into tbl_notice values
(notice_no_seq.nextval, '카카오톡 플러스친구 추가 이벤트 안내', 
'헬스자바 카카오톡 플러스친구를 추가해주신 고객님들께 최대 10% 할인 쿠폰을 제공해 드립니다.
자세한 사항은 플러스친구를 추가하시어 확인하시기 바랍니다.', sysdate);

insert into tbl_notice values(notice_no_seq.nextval, '오프라인 개인정보처리방침 개정안내', '제 3조(헬스자바가 수집하는 개인정보 항목 및 수집방법) 내용이 추가될 예정입니다.', sysdate);

select * from tbl_notice;

-----------------------------------------------------------------------------------------------
/*자주 묻는 질문 더미데이터*/


--자주 묻는 질문 '로그인/정보' 더미데이터
insert into tbl_faq values(faq_no_seq.nextval, '로그인/정보', '상품구매시 어떤 회원 혜택이 있나요?', 
'쇼핑몰에서 상품을 최초 구매하시고, 구매확정 시 다음 구매에 사용하실 수 있는 7% 할인쿠폰을 드립니다.');
insert into tbl_faq values(faq_no_seq.nextval, '로그인/정보', '탈퇴 후 재가입이 가능한가요?', 
'네. 가능합니다. 단, 탈퇴일 기준 1달 이내에는 재가입이 불가합니다. 신중하게 진행해주시기 바랍니다. ');
insert into tbl_faq values(faq_no_seq.nextval, '로그인/정보', '아이디를 변경하고 싶습니다. 가능한가요?', 
'아니요. 아이디(ID) 변경은 불가합니다. 새로운 아이디(ID)로 이용하고자 하실 경우, 탈퇴 후 재가입을 진행하셔야 합니다.');
insert into tbl_faq values(faq_no_seq.nextval, '로그인/정보', '개명으로 이름을 변경하고 싶습니다. 어떻게 해야하나요?', 
'개명으로 이름을 변경하고 싶으신 경우, 마이페이지 → 회원정보 변경에서 가능합니다.');
insert into tbl_faq values(faq_no_seq.nextval, '로그인/정보', '비밀번호를 변경하고 싶습니다. 어떻게 해야하나요?', 
'비밀번호를 변경하고 싶으신 경우, 마이페이지 → 비밀번호 변경에서 가능합니다.');

--자주 묻는 질문 '주문/결제' 더미데이터
insert into tbl_faq values(faq_no_seq.nextval, '주문/결제', '비회원도 주문이 가능한가요?', '비회원도 주문 가능합니다. 단, 비회원으로 주문 시 각종 할인이나 적립금 혜택은 받으실 수 없습니다.');
insert into tbl_faq values(faq_no_seq.nextval, '주문/결제', '결제 수단별 환불처리 기간을 알고 싶어요.', 
'① 신용카드 : 신용카드 승인취소는 매입(카드사로 결제정보가 넘어가기 전)인 경우에는 취소 승인한 당일 취소됩니다.
 ② 무통장 입금: 취소신청 확인 후 입력된 환불계좌로 익일(영업일기준) 환불됩니다. ');
insert into tbl_faq values(faq_no_seq.nextval, '주문/결제', '주문 하고 싶은 제품이 품절입니다. 어떻게 해야되나요?', 
'품절이라고 되어있는 제품은 고객님들의 수요에 따라 입고가 결정됩니다. 보다 자세한 사항은 1대1 문의 부탁드립니다.');
insert into tbl_faq values(faq_no_seq.nextval, '주문/결제', '제품별 무이자 할부 여부/개월 수는 어떻게 확인하나요?',
'무이자할부 여부/ 무이자할부 개월 수 확인 방법 안내드립니다.
① 구매하고 하는 상품을 선택한 후 구매하기 버튼 클릭
② 상품 주문서 페이지 하단> 결제방법 > 신용카드 탭  클릭
③ 결제하고자 하는 카드 종류 선택
④ 할부종류에서 무이자할부 가능 여부 및 개월 수 확인');
insert into tbl_faq values(faq_no_seq.nextval, '주문/결제', '주문 후 결제했던 카드를 변경할 수 있나요?', 
'결제 완료 후 다른 카드로 변경하는 것은 불가능합니다.
주문 취소 후 재 주문해주셔야합니다. 양해 부탁드립니다.');

--자주 묻는 질문 '배송문의' 더미데이터
insert into tbl_faq values(faq_no_seq.nextval, '배송문의', '기본 배송지 관리는 어떻게 하나요?', 
'기본 배송지 변경은 마이페이지 →  배송지 관리 메뉴 배송지 수정이 가능합니다. ');
insert into tbl_faq values(faq_no_seq.nextval, '배송문의', '주문 후 배송지 변경이 가능한가요?', 
'제품이 출고된 이후에는 배송지 변경이 어렵습니다. 
배송지 변경가능 여부는 배송지 변경 가능여부는 1:1문의 또는 고객센터를 통해 문의주시면 도와드리겠습니다. ');
insert into tbl_faq values(faq_no_seq.nextval, '배송문의', '배송기간은 얼마나 걸리나요?', 
'배송기간은 배송방법과 고객님의 수령지역에 따라 차이가 있을 수 있으며 대략 3~5일정도 소요 됩니다.');
insert into tbl_faq values(faq_no_seq.nextval, '배송문의', '배송단계는 어떻게 되나요?', 
'결제완료후 관리자가 주문 내역을 확인 후 상품 준비가 완료되면 배송이 시작됩니다.');
insert into tbl_faq values(faq_no_seq.nextval, '배송문의', '배송업체는 어떻게 되나요?', 
'배송업체는 매번 다를 수 있습니다. 보다 자세한 사항은 1대1로 문의 부탁드립니다.');

--자주 묻는 질문 '교환/취소(반품)' 더미데이터
insert into tbl_faq values(faq_no_seq.nextval, '교환/취소(반품)', '어떠한 경우에 반품이 가능한가요?', 
'전자상거래 등에서의 소비자 보호에 관한 법률 17조에 의거하여 배송 완료 후 7일 이내 교환/반품 신청이 가능합니다.');
insert into tbl_faq values(faq_no_seq.nextval, '교환/취소(반품)', '교환/반품 처리기간은 얼마나 되나요?', 
'교환 및 반품의 처리 기간은 상품에 따라 다를 수 있으며, 재고 여부(교환 시) 및 택배사 사정에 의해 처리 및 배송이 지연될 수 있습니다. 
(교환 및 반품의 경우 회수 상품 입고되어, 검품 후 환불처리 및 교환배송이 진행됩니다)');
insert into tbl_faq values(faq_no_seq.nextval, '교환/취소(반품)', '여러개를 동시 주문했는데, 일부 상품만 취소 할 수 있나요?', 
'여러개 주문 시 일부상품에 대한 부분 취소/반품/교환이 가능합니다. 
 ※ 단, 반품/교환은 주문한 상품이 배송완료 되었을 경우 진행 가능합니다.');
 insert into tbl_faq values(faq_no_seq.nextval, '교환/취소(반품)', '환불은 어떻게 가능한가요?', 
'결제했던 카드로 취소신철을 하시면 환불 가능합니다.');
insert into tbl_faq values(faq_no_seq.nextval, '교환/취소(반품)', '카드환불 완료 기간은 어떻게 되나요?', 
'카드사마다 다르지만 대체로 영업일 기준으로 3~5일 정도 소요됩니다. ');

select * from tbl_faq;

-----------------------------------------------------------------------------------------------
/*1대1 문의게시판 더미데이터*/
insert into tbl_client values(client_no_seq.nextval, '비밀번호가 기억이 안나요', '1234',  '어떻게하죠?', '비밀번호 찾기 서비스를 이용해주세요', '로그인/정보', '2023-04-25', 'test01');
insert into tbl_client values(client_no_seq.nextval, '배송 얼마나 걸려요?', '1234', '주문한지 2일정도 지났는데', '배송일은 3~5일 정도 소요됩니다', '배송문의', '2023-05-06', 'test01');
insert into tbl_client values(client_no_seq.nextval, '상품이 스크레치가 났어요', '1234', '어떻게 된거죠?', '죄송합니다. 배송중 사고로 보입니다. 확인 후 교환/반품 처리 해드리겠습니다.', '배송문의', '2023-05-15', 'test02');
insert into tbl_client values(client_no_seq.nextval, '상품 주문을 취소하고 싶습니다.','1234', '결제는 아직 안했어요', '마이페이지 → 주문취소에서 취소 가능합니다. ', '교환/취소(반품)', '2023-05-20', 'test03');
insert into tbl_client values(client_no_seq.nextval, '결제수단을 바꾸고 싶어요','1234', '어떻게 해야하죠?', '이미 결제가 완료된 상품은 변경이 불가능합니다. 결제 취소후 재주문 부탁드립니다. ', '주문/결제', sysdate, 'test03');

commit;
