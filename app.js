const express = require("express");
const path = require("path");
const app = express();
const session = require('express-session');
const con = require("./config/db");
const bcrypt = require('bcrypt');
const passport = require('passport');
const saltRounds = 10;
const expressLayouts = require('express-ejs-layouts');
const formidable = require('formidable');
const XLSX = require('xlsx');
const multer = require("multer");
const fs = require("fs");
const mysql = require('mysql');

const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


const upload = multer({ dest: "uploads/" });

app.get('/getStudentId', (req, res) => {
  const email = req.query.email;
  con.query('SELECT studentid FROM students WHERE email = ?', [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (results.length > 0) {
      res.json({ studentid: results[0].studentid });
    } else {
      res.status(404).json({ message: 'Student not found' });
    }
  });
});


app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});


let bookmarks = [];

app.use(express.static(path.join(__dirname, "public")));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'SECRET',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

const userAdmin = ["CHOMPHUNUT", "WACHIRARAT",];

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect('/login');
  }
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    return next();
  } else {
    res.redirect('/dashboard');
  }
}



app.post("/login", isAuthenticated, (req, res) => {
  const { username, password } = req.body;

  const sql = "SELECT id, username, password, role, studentid FROM user WHERE username = ?";
  con.query(sql, [username], (err, results) => {
    if (err) {
      return res.status(500).send("Database error.");
    }
    if (results.length === 0) {
      return res.status(401).json({ message: "Wrong username or password" });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).send("Error checking password.");
      }
      if (!isMatch) {
        return res.status(401).json({ message: "Wrong username or password" });
      }

      req.session.user = { id: user.id, username: user.username, role: user.role, studentid: user.studentid };

      res.json({
        redirect: user.role === 2 ? '/dashboardadmin' : '/dashboard',
        studentId: user.studentid
      });
    });
  });
});

app.post('/auth/google', (req, res) => {
  try {
    const userinfo = req.body.userinfo;

    if (!userinfo) {
      return res.status(400).json({ error: 'No user info provided' });
    }

    console.log('Userinfo received:', userinfo);

    const getNameFromEmail = (email) => {
      const namePart = email.split('@')[0];
      return namePart
        .split('.')
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join(' ');
    };

    const displayName = userinfo.displayName || userinfo.fullname || getNameFromEmail(userinfo.email);

    const isAdmin = userinfo.email.toLowerCase().includes('oraphan');
    console.log('isAdmin:', isAdmin);

    const sqlCheck = "SELECT * FROM student WHERE email = ?";
    con.query(sqlCheck, [userinfo.email], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (results.length === 0) {

        const sqlInsert = `INSERT INTO student 
          (email, facultyid, majorid, role, first_name, last_name, display_name, studentid) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        const randomFaculty = Math.floor(Math.random() * 10) + 1;
        const randomMajor = Math.floor(Math.random() * 10) + 1;
        const randomStudentId = Math.floor(Math.random() * 1000000);
        const [firstName, lastName] = displayName.split(' ').length > 1
          ? displayName.split(' ')
          : [displayName, ''];
        const role = isAdmin ? 'admin' : 'student';

        con.query(sqlInsert, [userinfo.email, randomFaculty, randomMajor, role, firstName, lastName, displayName, randomStudentId], (err, result) => {
          if (err) {
            console.error('Error inserting data:', err);
            return res.status(500).json({ error: 'Error inserting data' });
          }
          req.session.user = {
            id: randomStudentId,
            email: userinfo.email,
            firstName,
            lastName,
            displayName,
            role,
            studentid: randomStudentId,
          };

          console.log('New user inserted:', result.insertId);
          console.log('User displayName:', req.session.user.displayName);
          console.log('User role:', req.session.user.role);

          if (isAdmin) {
            res.redirect('/dashboardadmin');
          } else {
            res.json({
              success: true,
              role: req.session.user.role,
              studentid: req.session.user.studentid,
            });
          }
        });
      } else {
        const student = results[0];
        const displayName = userinfo.displayName || student.display_name;
        const role = isAdmin ? 'admin' : student.role;
        req.session.user = {
          id: student.studentid,
          email: userinfo.email,
          firstName: student.first_name,
          lastName: student.last_name,
          displayName,
          role,
          studentid: student.studentid,
        };

        console.log('Found existing student:', student);
        console.log('User displayName:', req.session.user.displayName);
        console.log('User role:', req.session.user.role);

        if (isAdmin) {
          res.redirect('/dashboardadmin');
        } else {
          res.json({
            success: true,
            role: req.session.user.role,
            studentid: req.session.user.studentid,
          });
        }
      }
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});




app.get('/importstudent', (req, res) => {
  res.render('importstudent');
});

app.get('/seelist', (req, res) => {
  res.render('seelist');
});










app.get("/history", (req, res) => {
  const studentId = req.session.user.id;

  if (!studentId) {
    return res.redirect('/login');
  }

  const query = `
    SELECT 
        c.id AS course_id,
        c.name AS course_name, 
        c.code AS course_code, 
        c.rating AS course_rating
    FROM 
        student_course_history sch
    JOIN 
        coursee c ON sch.course_id = c.id
    WHERE 
        sch.studentid = ?;
  `;

  con.query(query, [studentId], (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Error retrieving course history");
    }
    res.render("historycourese", {
      title: "History Page",
      courses: results,
    });
  });
});





app.post('/submit-review', (req, res) => {
  const student_id = req.session.user?.id;

  if (!student_id) {
    return res.status(400).send('User not logged in');
  }

  const { course_id, rate_easy, rate_collect, rate_registration, rate_content, rate_overview, review_detail } = req.body;

  const totalRating = parseFloat(rate_easy) + parseFloat(rate_collect) + parseFloat(rate_registration) + parseFloat(rate_content) + parseFloat(rate_overview);
  const averageRating = (totalRating / 5).toFixed(2);

  const insertReviewQuery = `
    INSERT INTO course_reviews (course_id, student_id, rate_easy, rate_collect, rate_registration, rate_content, rate_overview, review_detail, average)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  con.query(
    insertReviewQuery,
    [course_id, student_id, rate_easy, rate_collect, rate_registration, rate_content, rate_overview, review_detail, averageRating],
    (err, result) => {
      if (err) {
        console.error('Error inserting review:', err);
        return res.status(500).send('Error inserting review');
      }

      const recalculateRatingQuery = `
        SELECT SUM(average) AS totalRating, COUNT(*) AS reviewCount
        FROM course_reviews
        WHERE course_id = ?
      `;

      con.query(recalculateRatingQuery, [course_id], (err, ratingResults) => {
        if (err) {
          console.error('Error recalculating course rating:', err);
          return res.status(500).send('Error recalculating course rating');
        }

        const totalRating = ratingResults[0]?.totalRating || 0;
        const reviewCount = ratingResults[0]?.reviewCount || 0;

        console.log(`Total rating: ${totalRating}, Review count: ${reviewCount}`);

        const newAverageRating = (totalRating / reviewCount).toFixed(2);

        console.log(`Recalculated new average rating for course ${course_id}: ${newAverageRating}`);

        const updateCourseQuery = `
          UPDATE coursee
          SET rating = ?
          WHERE id = ?
        `;

        con.query(updateCourseQuery, [newAverageRating, course_id], (err, updateResult) => {
          if (err) {
            console.error('Error updating course rating:', err);
            return res.status(500).send('Error updating course rating');
          }

          console.log(`Course ${course_id} updated with new rating: ${newAverageRating}`);
          res.redirect(`/course/${course_id}`);
        });
      });
    }
  );
});



app.get('/seesearch', (req, res) => {
  const { name, field_of_study, type, academic_year, semester } = req.query;
  let sql = 'SELECT * FROM coursee WHERE 1=1';
  const params = [];
  if (name) {
    sql += ' AND name LIKE ?';
    params.push(`%${name}%`);
  }
  if (field_of_study) {
    sql += ' AND field_of_study = ?';
    params.push(field_of_study);
  }
  if (type) {
    sql += ' AND type = ?';
    params.push(type);
  }
  if (academic_year) {
    sql += ' AND academic_year = ?';
    params.push(academic_year);
  }
  if (semester) {
    sql += ' AND semester = ?';
    params.push(semester);
  }

  con.query(sql, params, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send('Error fetching data from the database.');
    }

    const dropdownQueries = [
      { query: 'SELECT DISTINCT field_of_study FROM coursee', key: 'field_of_studys' },
      { query: 'SELECT DISTINCT type FROM coursee', key: 'types' },
      { query: 'SELECT DISTINCT academic_year FROM coursee', key: 'academicYears' },
      { query: 'SELECT DISTINCT semester FROM coursee', key: 'semesters' },
    ];

    const promises = dropdownQueries.map(queryObj => {
      return new Promise((resolve, reject) => {
        con.query(queryObj.query, (err, dropdownResults) => {
          if (err) reject(err);
          resolve({ key: queryObj.key, data: dropdownResults });
        });
      });
    });

    Promise.all(promises)
      .then(resultsDropdown => {
        const dropdownData = resultsDropdown.reduce((acc, item) => {
          acc[item.key] = item.data;
          return acc;
        }, {});


        res.render('seesearch', {
          courses: results,
          searchParams: req.query,
          dropdownData
        });
      })
      .catch(err => {
        console.error("Error fetching dropdown data:", err);
        res.status(500).send('Error fetching dropdown data.');
      });
  });
});







app.get("/searchcourse", function (req, res) {
  const searchParams = req.query;
  const { name, field_of_study, type, academic_year, semester } = searchParams;


  const dropdownData = {
    field_of_studys: [/* array of school options */],
    types: [/* array of course types */],
    academicYears: [/* array of academic years */],
    semesters: [/* array of semesters */]
  };


  const sql = `
      SELECT * FROM courses
      WHERE 
          (name LIKE ? OR ? IS NULL)
          AND (field_of_study LIKE ? OR ? IS NULL)
          AND (type LIKE ? OR ? IS NULL)
          AND (academic_year LIKE ? OR ? IS NULL)
          AND (semester LIKE ? OR ? IS NULL)
  `;

  const values = [
    `%${name}%`, name,
    `%${field_of_study}%`, field_of_study,
    `%${type}%`, type,
    `%${academic_year}%`, academic_year,
    `%${semester}%`, semester
  ];

  con.query(sql, values, (err, results) => {
    if (err) {
      console.error('Error fetching courses:', err);
      return res.status(500).send('Error fetching courses');
    }


    res.render('searchcourses', {
      courses: results,
      searchParams: searchParams,
      dropdownData
    });
  });
});



app.get("/listcoursesee", function (req, res) {
  const sql = 'SELECT id, code, name, rating, type FROM coursee';

  con.query(sql, (err, results) => {
    if (err) {
      console.error("Error in fetching data from the database:", err);
      return res.status(500).send("Error in fetching data from the database.");
    }


    res.json({
      courses: results
    });
  });
});

app.get("/seelist", function (req, res) {

  const { name, type, rating } = req.query;

  let sql = 'SELECT id, code, name, rating, type FROM coursee';
  let filters = [];


  if (name) {
    filters.push(`name LIKE '%${name}%'`);
  }
  if (type) {
    filters.push(`type LIKE '%${type}%'`);
  }
  if (rating) {
    filters.push(`rating >= ${rating}`);
  }


  if (filters.length > 0) {
    sql += ' WHERE ' + filters.join(' AND ');
  }


  con.query(sql, (err, results) => {
    if (err) {
      console.error("Error in fetching data from the database:", err);
      return res.status(500).send("Error in fetching data from the database.");
    }


    res.render('seelist', { courses: results });
  });
});







app.get("/listcourse", isAuthenticated, function (req, res) {
  const userEmail = req.session.user?.email;

  if (!userEmail) {
    return res.status(401).send("Unauthorized access. Please log in.");
  }

  const sql = 'SELECT id, code, name, rating, type FROM coursee';

  con.query(sql, (err, results) => {
    if (err) {
      console.error("Error in fetching data from the database:", err);
      return res.status(500).send("Error in fetching data from the database.");
    }

    let filteredCourses;
    let isMajorElectiveVisible = userEmail.includes('31501');


    if (userEmail.endsWith('@lamduan.mfu.ac.th') && userEmail.includes('31501')) {
      filteredCourses = results;
    } else {

      filteredCourses = results.filter(course => course.type === 'Free Elective');
    }


    res.render('listcourses', {
      courses: filteredCourses,
      showMajorElective: isMajorElectiveVisible
    });
  });
});







app.get('/course/:id', (req, res) => {
  const courseId = req.params.id;
  const user = req.session.user;


  const userEmail = req.session.user ? req.session.user.email : 'Guest';
  const firstName = req.session.user ? req.session.user.firstName : '';
  const lastName = req.session.user ? req.session.user.lastName : '';


  const queryCourse = 'SELECT * FROM coursee WHERE id = ?';
  const queryReviews = `
   SELECT 
    cr.*, 
    s.studentid AS student_id,
    s.email AS student_email,
    s.first_name AS student_first_name,
    s.last_name AS student_last_name
  FROM course_reviews cr
  JOIN student s ON cr.student_id = s.studentid
  WHERE cr.course_id = ?
  ORDER BY cr.created_at DESC
`;


  con.query(queryCourse, [courseId], (err, courseDetails) => {
    if (err) {
      console.error('Error fetching course details:', err);
      return res.status(500).send('Error fetching course details.');
    }


    if (courseDetails.length === 0) {
      return res.status(404).send('Course not found.');
    }

    con.query(queryReviews, [courseId], (err, courseReviews) => {
      if (err) {
        console.error('Error fetching course reviews:', err);
        return res.status(500).send('Error fetching course reviews.');
      }


      const reviewsWithScores = courseReviews.map((review) => {
        const totalNormalizedScore = (
          (review.rate_easy / 5) +
          (review.rate_collect / 5) +
          (review.rate_registration / 5) +
          (review.rate_content / 5) +
          (review.rate_overview / 5)
        );

        return {
          ...review,
          total_normalized_score: totalNormalizedScore.toFixed(1),
          studentName: `${review.student_first_name} ${review.student_last_name}`,
          studentId: review.student_id,
        };
      });


      res.render('coursedetail', {
        course: courseDetails[0],
        reviews: reviewsWithScores,
        userEmail,
        firstName,
        lastName,
        user,
      });
    });
  });
});


app.delete('/review/:id', (req, res) => {
  const reviewId = req.params.id;


  const deleteQuery = 'DELETE FROM course_reviews WHERE id = ?';

  con.query(deleteQuery, [reviewId], (err, result) => {
    if (err) {
      console.error('Error deleting review:', err);
      return res.status(500).send('Error deleting review.');
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('Review not found.');
    }
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Unauthorized action.');
    }

    res.status(200).send('Review deleted successfully.');
  });
});














app.get('/review/:course_id', isAuthenticated, (req, res) => {
  const courseId = req.params.course_id;


  const queryCourse = 'SELECT * FROM coursee WHERE id = ?';
  con.query(queryCourse, [courseId], (err, courseDetails) => {
    if (err) {
      console.error("Error fetching course details:", err);
      return res.status(500).send('Error fetching course details.');
    }


    if (courseDetails.length === 0) {
      return res.status(404).send('Course not found.');
    }


    res.render('review_courses', {
      course: courseDetails[0],
      user: req.session.user,
      userEmail: req.session.user.email
    });
  });
});

function authenticateUser(req, res, next) {
  if (req.session && req.session.user) {

    next();
  } else {

    return res.status(401).json({ error: 'Unauthorized. Please log in first.' });
  }
}

function authenticateUser(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized. Please log in first.' });
  }
}


let notifications = [];


function sendDeletionNotification(studentId, message) {
  const notification = {
    studentId,
    message,
    createdAt: new Date().toISOString(),
  };
  notifications.push(notification);
  console.log('Notification sent successfully:', notification);
}


app.get('/api/notifications', authenticateUser, async (req, res) => {
  try {
    const studentId = req.session.user.studentid;
    const userEmail = req.session.user.email;

    if (!studentId || !userEmail) {
      return res.status(401).json({ error: 'User not authenticated' });
    }


    const [dbNotifications] = await con.promise().query(
      `SELECT c.commentdetail AS message, 
              c.commenttime AS createdAt, 
              p.postid, 
              p.postdetail AS posttitle, 
              CONCAT(s.first_name, ' ', s.last_name) AS commenter  
       FROM comment c
       JOIN postt p ON c.postid = p.postid
       JOIN student s ON c.email = s.email
       WHERE p.email = ?
       ORDER BY c.commenttime DESC`,
      [userEmail]
    );


    const combinedNotifications = [...notifications.filter(n => n.studentId == studentId), ...dbNotifications];

    res.status(200).json({ notifications: combinedNotifications });
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/api/comments', (req, res) => {
  const postId = req.query.postId;

  if (!postId) {
    return res.status(400).json({ error: 'Post ID is required' });
  }

  const query = 'SELECT commentdetail, email FROM comment WHERE postid = ?';
  con.query(query, [postId], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Database query error' });
    }
    res.status(200).json({ comments: results });
  });
});










app.delete('/review/delete/:reviewId', (req, res) => {
  const reviewId = req.params.reviewId;


  const getReviewQuery =
    `
    SELECT r.student_id, c.name AS course_name
    FROM course_reviews r
    JOIN coursee c ON r.course_id = c.id
    WHERE r.id = ?`
    ;


  const deleteQuery = 'DELETE FROM course_reviews WHERE id = ?';


  con.query(getReviewQuery, [reviewId], (err, result) => {
    if (err) {
      console.error('Error fetching review details:', err);
      return res.status(500).json({ success: false, message: 'Error fetching review information.' });
    }

    if (result.length === 0) {
      return res.status(404).json({ success: false, message: 'Review not found.' });
    }

    const studentId = result[0].student_id;
    const courseName = result[0].course_name;


    con.query(deleteQuery, [reviewId], (err, deleteResult) => {
      if (err) {
        console.error('Error deleting review:', err);
        return res.status(500).json({ success: false, message: 'Error deleting review.' });
      }

      if (deleteResult.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Review not found.' });
      }


      const notificationMessage = `Your review with the details: "${courseName}" has been deleted by an admin.`;
      sendDeletionNotification(studentId, notificationMessage,);

      return res.json({ success: true, message: 'Review deleted successfully.' });
    });
  });
});



































app.get('/post', (req, res) => {
  res.render('post');
});





app.get('/notireview', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/notireview.html'));
});

app.get('/noticommu', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/noticommu.html'));
});



app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Failed to logout' });
    }
    res.status(200).json({ redirect: '/login' });
  });
});



let posts = [];
let comments = {};


app.post('/submit-post', (req, res) => {
  const postContent = req.body.postContent;
  const postId = posts.length;
  posts.push(postContent);
  comments[postId] = [];

  res.redirect('/community');
});














app.get('/community', (req, res) => {
  const userinfo = req.session.userinfo;
  const isAdmin = userinfo && userinfo.email === '6431501124@lamduan.mfu.ac.th';


  res.render('community', { posts: posts, comments: comments, isAdmin: isAdmin, userinfo: userinfo });
});




















app.post('/api/import', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const filePath = req.file.path;

  try {

    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName]);

    console.log('Parsed Data:', data);

    if (!data.length) {
      return res.status(400).json({ message: 'Excel file is empty' });
    }

    const queries = [];
    const insertedData = [];

    data.forEach((row) => {
      const email = row.email;
      const courseCode = row.course_code;

      if (!email || !courseCode) {
        console.warn('Invalid row data:', row);
        return;
      }

      const query = `
        INSERT INTO student_course_history (studentid, course_id)
        SELECT 
            s.studentid, c.id
        FROM student s
        INNER JOIN coursee c ON c.code = ?
        WHERE s.email = ?
        AND NOT EXISTS (
          SELECT 1 
          FROM student_course_history sch
          WHERE sch.studentid = s.studentid AND sch.course_id = c.id
        );
      `;

      console.log(`Inserting data: email=${email}, courseCode=${courseCode}`);

      queries.push(
        new Promise((resolve, reject) => {
          con.query(query, [courseCode, email], (err, result) => {
            if (err) {
              console.error('Error inserting data:', err);
              reject(err);
            } else if (result.affectedRows > 0) {
              insertedData.push({ email, courseCode });
            }
            resolve(result);
          });
        })
      );
    });

    Promise.all(queries)
      .then(() => {
        console.log('Inserted Data:', insertedData);
        res.json({ message: 'File imported successfully!', data: insertedData });
      })
      .catch((err) => {
        console.error('Error during import:', err);
        res.status(500).json({ message: 'Error inserting data into database.' });
      });
  } catch (err) {
    console.error('Error reading the file:', err);
    res.status(500).json({ message: 'Error reading the file.' });
  } finally {

    fs.unlink(filePath, (err) => {
      if (err) console.error('Error removing uploaded file:', err);
    });
  }
});

app.get('/api/getUploadedData', (req, res) => {
  const query = `
    SELECT s.email, c.code AS courseCode
    FROM student_course_history sch
    JOIN student s ON sch.studentid = s.studentid
    JOIN coursee c ON sch.course_id = c.id
  `;

  con.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ message: 'Error fetching data from the database.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'No data found.' });
    }

    res.json({ data: results });
  });
});
app.delete('/api/deleteData', (req, res) => {
  const { email, courseCode } = req.body;

  const query = `
      DELETE FROM student_course_history
      WHERE studentid = (SELECT studentid FROM student WHERE email = ?)
      AND course_id = (SELECT id FROM coursee WHERE code = ?);
  `;

  con.query(query, [email, courseCode], (err, result) => {
    if (err) {
      console.error('Error deleting data:', err);
      return res.status(500).json({ message: 'Failed to delete data.' });
    }

    res.json({ message: 'Data deleted successfully.' });
  });
});

app.get('/api/getAllData', (req, res) => {
  const query = `
      SELECT s.email, c.code AS courseCode
      FROM student_course_history sch
      JOIN student s ON sch.studentid = s.studentid
      JOIN coursee c ON sch.course_id = c.id;
  `;

  con.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ message: 'Error fetching data from the database.' });
    }

    res.json(results);
  });
});




















app.post('/bookmark/add', isAuthenticated, (req, res) => {
  const { course_id } = req.body;
  const student_id = req.session.user.studentid;

  const sqlCheck = 'SELECT * FROM bookmarks WHERE course_id = ? AND student_id = ?';
  console.log('Executing sqlCheck:', sqlCheck, 'with values:', course_id, student_id);

  con.query(sqlCheck, [course_id, student_id], (err, results) => {
    if (err) {
      console.error('Database error during sqlCheck:', err);
      return res.status(500).json({ success: false, message: 'Database error.' });
    }

    if (results.length === 0) {
      const sqlInsert = 'INSERT INTO bookmarks (course_id, student_id) VALUES (?, ?)';
      console.log('Executing sqlInsert:', sqlInsert, 'with values:', course_id, student_id);

      con.query(sqlInsert, [course_id, student_id], (err) => {
        if (err) {
          console.error('Database error during sqlInsert:', err);
          return res.status(500).json({ success: false, message: 'Failed to bookmark the course.' });
        }
        return res.json({ success: true, message: 'Bookmark added.' });
      });
    } else {
      return res.json({ success: false, message: 'Already bookmarked.' });
    }
  });
});








app.get('/bookmark', isAuthenticated, (req, res) => {
  const student_id = req.session.user.studentid;

  const sql = `
    SELECT coursee.id, coursee.name, coursee.code, coursee.rating
    FROM bookmarks
    JOIN coursee ON bookmarks.course_id = coursee.id
    WHERE bookmarks.student_id = ?
  `;
  console.log('id: ', req.session.user.studentid)




  con.query(sql, [student_id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Database error.');
    }


    res.render('bookmarks', { bookmarks: results });
  });
});





app.post('/bookmark/remove', isAuthenticated, (req, res) => {
  const { course_id } = req.body;
  const student_id = req.session.user.studentid;

  const sqlDelete = 'DELETE FROM bookmarks WHERE course_id = ? AND student_id = ?';
  console.log('Executing sqlDelete:', sqlDelete, 'with values:', course_id, student_id);

  con.query(sqlDelete, [course_id, student_id], (err) => {
    if (err) {
      console.error('Database error during sqlDelete:', err);
      return res.status(500).json({ success: false, message: 'Failed to remove bookmark.' });
    }
    return res.json({ success: true, message: 'Bookmark removed.' });
  });
});










app.delete('/deleteCourse/:id', async (req, res) => {
  const courseId = req.params.id;

  try {

    await con.promise().query('DELETE FROM bookmarks WHERE course_id = ?', [courseId]);


    const [result] = await con.promise().query('DELETE FROM coursee WHERE id = ?', [courseId]);


    if (result.affectedRows > 0) {
      res.status(200).json({ message: 'Course and related bookmarks deleted successfully' });
    } else {
      res.status(404).json({ message: 'Course not found' });
    }
  } catch (err) {
    console.error('Error deleting course:', err);
    res.status(500).json({ message: 'Error deleting course', error: err.message });
  }
});






app.post('/uploadCourses', (req, res) => {
  try {
    const coursesData = req.body.data;

    console.log('Data received from client:', coursesData);


    if (!coursesData || coursesData.length === 0) {
      console.log('No data received from the client.');
      return res.status(400).json({ message: 'No data received' });
    }


    const rows = coursesData.slice(1);
    const values = rows.map((row) => {
      const code = row[7];
      if (!code) {
        console.warn('Skipping row due to missing "code":', row);
        return null;
      }
      return {
        id: row[0],
        name: row[1],
        school: row[2],
        field_of_study: row[3],
        credit: row[4],
        course_status: row[5],
        description: row[6],
        code: code,
        rating: row[8],
        academic_year: row[9],
        semester: row[10],
        type: row[11],
      };
    }).filter((row) => row !== null);

    console.log('Filtered values for insertion:', JSON.stringify(values, null, 2));

    if (values.length === 0) {
      console.error('No valid rows to insert after filtering.');
      return res.status(400).json({ message: 'No valid rows to insert.' });
    }


    const insertSql = `
      INSERT INTO coursee (id, name, school, field_of_study, credit, course_status, description, code, rating, academic_year, semester, type)
      VALUES ?
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        school = VALUES(school),
        field_of_study = VALUES(field_of_study),
        credit = VALUES(credit),
        course_status = VALUES(course_status),
        description = VALUES(description),
        rating = VALUES(rating),
        academic_year = VALUES(academic_year),
        semester = VALUES(semester),
        type = VALUES(type)
    `;

    const valuesArray = values.map(Object.values);


    con.query(insertSql, [valuesArray], (err) => {
      if (err) {
        console.error('Database error during insert/update:', err);
        return res.status(500).json({ message: 'Database insertion failed.', error: err });
      }

      console.log('Insert/Update successful.');


      const codesInExcel = values.map((course) => course.code);


      const deleteSql = `
        DELETE FROM coursee
        WHERE code NOT IN (?)
      `;


      con.query(deleteSql, [codesInExcel], (err) => {
        if (err) {
          console.error('Database error during delete:', err);
          return res.status(500).json({ message: 'Database deletion failed.', error: err });
        }

        console.log('Outdated courses successfully deleted.');
        res.status(200).json({ message: 'Courses uploaded and outdated courses deleted successfully!' });
      });
    });
  } catch (error) {
    console.error('Error in /uploadCourses route:', error);
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});



app.get('/getCourses', (req, res) => {
  console.log('Received request on /getCourses');

  const selectSql = `
    SELECT id, name, school, field_of_study, credit, course_status, description, code, rating, academic_year, semester, type
    FROM coursee
  `;

  con.query(selectSql, (err, results) => {
    if (err) {
      console.error('Database retrieval error:', err);
      return res.status(500).json({ message: 'Database retrieval failed', error: err });
    }

    console.log('Courses data retrieved successfully.');
    res.status(200).json(results);
  });
});

const cors = require('cors');
app.use(cors());



app.get('/reviewsqty', (req, res) => {
  const sql = `
  SELECT 
    (SELECT COUNT(DISTINCT studentid) FROM student_course_history) AS total_reviews, 
    (SELECT COUNT(*) FROM coursee) AS total_courses_open,
    (SELECT COUNT(DISTINCT course_reviews.student_id) 
     FROM course_reviews 
     JOIN coursee ON course_reviews.course_id = coursee.id 
     WHERE coursee.type = 'Free Elective') AS total_free_reviews,
    (SELECT COUNT(DISTINCT course_reviews.student_id) 
     FROM course_reviews 
     JOIN coursee ON course_reviews.course_id = coursee.id 
     WHERE coursee.type = 'Major Elective') AS total_major_reviews;
`;



  con.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ errMsg: 'Error fetching data' });
    }

    const totalReviews = results[0].total_reviews;
    const totalCoursesOpen = results[0].total_courses_open;
    const totalFreeReviews = results[0].total_free_reviews;
    const totalMajorReviews = results[0].total_major_reviews;


    res.json({
      res: true,
      totalReviews,
      totalCoursesOpen,
      totalFreeReviews,
      totalMajorReviews
    });
  });
});







app.get('/reviewChart', (req, res) => {
  const sql = 'SELECT name AS NAME, rating AS RATE FROM coursee ORDER BY rating DESC LIMIT 10';

  con.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ errMsg: 'Error fetching data' });
    }


    res.json({ res: true, data: results });
  });
});



app.get('/search', isAuthenticated, (req, res) => {

  const { name, field_of_study, type, academic_year, semester } = req.query;


  let sql = 'SELECT * FROM coursee WHERE 1=1';
  const params = [];


  if (name) {
    sql += ' AND name LIKE ?';
    params.push(`%${name}%`);
  }
  if (field_of_study) {
    sql += ' AND field_of_study = ?';
    params.push(field_of_study);
  }
  if (type) {
    sql += ' AND type = ?';
    params.push(type);
  }
  if (academic_year) {
    sql += ' AND academic_year = ?';
    params.push(academic_year);
  }
  if (semester) {
    sql += ' AND semester = ?';
    params.push(semester);
  }


  con.query(sql, params, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send('Error fetching data from the database.');
    }


    const dropdownQueries = [
      { query: 'SELECT DISTINCT field_of_study FROM coursee', key: 'field_of_studys' },
      { query: 'SELECT DISTINCT type FROM coursee', key: 'types' },
      { query: 'SELECT DISTINCT academic_year FROM coursee', key: 'academicYears' },
      { query: 'SELECT DISTINCT semester FROM coursee', key: 'semesters' },
    ];


    const promises = dropdownQueries.map(queryObj => {
      return new Promise((resolve, reject) => {
        con.query(queryObj.query, (err, dropdownResults) => {
          if (err) reject(err);
          resolve({ key: queryObj.key, data: dropdownResults });
        });
      });
    });


    Promise.all(promises)
      .then(resultsDropdown => {

        const dropdownData = resultsDropdown.reduce((acc, item) => {
          acc[item.key] = item.data;
          return acc;
        }, {});


        res.render('search', {
          courses: results,
          searchParams: req.query,
          dropdownData
        });
      })
      .catch(err => {
        console.error("Error fetching dropdown data:", err);
        res.status(500).send('Error fetching dropdown data.');
      });
  });
});







app.get("/", (req, res) => {
  res.render('pages/index');
});

app.use("/assets", express.static(path.join(__dirname, "assets")));


app.get("/home", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "views/homepage.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "views/login0.html")));

app.get('/profile', (req, res) => {

  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userinfo = {
    email: req.session.user.email,
    fullname: req.session.user.firstName + ' ' + req.session.user.lastName,
    image: req.session.user.image || '',
  };


  res.render('profile', { user: userinfo });
});










app.get("/forgot", (req, res) => res.sendFile(path.join(__dirname, "views/forgot2.html")));

app.get("/community", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "views/community.html")));
app.get("/bookmark", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "views/bookmark.html")));
app.get("/notification", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "views/noticommu.html")));



app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/dashboard.html'));
});

app.get('/dashboardadmin', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/dashboardadmin.html'));
});


app.get("/register", (req, res) => {
  res.render('Register');
});
app.get("/listadmin", isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "views/admin_list.html")));

app.get('/commuadmin', (req, res) => {

  res.render('commuadmin', { posts: posts, comments: comments });
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/community', (req, res) => {

  const sqlQuery = `
    SELECT postt.postid, postt.postdetail, postt.posttime, COUNT(comment.commentid) AS commentCount
    FROM postt
    LEFT JOIN comment ON postt.postid = comment.postid
    GROUP BY postt.postid
    ORDER BY postt.posttime DESC;
  `;

  con.query(sqlQuery, (err, results) => {
    if (err) {
      console.error('Error fetching posts:', err);
      return res.status(500).send('Error fetching posts');
    }
    res.render('community', { posts: results });
  });
});
app.get('/community/getPosts', (req, res) => {
  const sqlQuery = `
      SELECT 
          postt.postid, 
          postt.postdetail, 
          postt.posttime, 
          COUNT(comment.commentid) AS commentCount,
          student.first_name,
          student.last_name
      FROM postt
      LEFT JOIN comment ON postt.postid = comment.postid
      LEFT JOIN student ON postt.email = student.email
      GROUP BY postt.postid
      ORDER BY postt.posttime DESC;;
  `;

  con.query(sqlQuery, (err, result) => {
    if (err) {
      console.error('Error fetching posts from MySQL:', err);
      return res.status(500).json({ message: 'Error fetching posts' });
    }
    res.json(result);
  });
});


app.post('/post', (req, res) => {
  const { postContent, email } = req.body;


  if (!postContent || !email) {
    return res.status(400).send('Post detail and email are required.');
  }

  const sql = 'INSERT INTO postt (postdetail, email) VALUES (?, ?)';
  con.query(sql, [postContent, email], (err, result) => {
    if (err) {
      console.error('Error inserting post:', err);
      return res.status(500).send('Database error: ' + (err.sqlMessage || err.message));
    }

    const newPost = {
      postid: result.insertId,
      postdetail: postContent,
      email: email,
      time: new Date(),
      comments: []
    };

    res.send({ message: 'Post added successfully', postId: result.insertId });
  });
});


app.get('/comment/:postid', (req, res) => {
  const postId = req.params.postid;
  const user = req.session.user || {};


  con.query('SELECT * FROM postt WHERE postid = ?', [postId], (err, postResults) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error fetching post');
    }

    if (postResults.length === 0) {
      return res.status(404).send('Post not found');
    }

    const post = postResults[0];


    con.query(
      `SELECT first_name, last_name 
           FROM student 
           WHERE email = ?`,
      [post.email],
      (err, userResult) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Error fetching post creator details');
        }

        const postCreator = userResult[0] || {};


        con.query(
          `SELECT comment.commentid, comment.commentdetail, student.first_name, student.last_name 
                   FROM comment 
                   JOIN student ON comment.email = student.email 
                   WHERE comment.postid = ?`,
          [postId],
          (err, commentsResults) => {
            if (err) {
              console.error(err);
              return res.status(500).send('Error fetching comments');
            }

            const comments = commentsResults.map(comment => ({
              commentid: comment.commentid,
              detail: comment.commentdetail,
              name: `${comment.first_name} ${comment.last_name}`
            }));


            res.render('comment', {
              post,
              postId,
              comments,
              user,
              postCreator: `${postCreator.first_name} ${postCreator.last_name}`
            });
          }
        );
      }
    );
  });
});









app.post('/submit-comment/:postId', (req, res) => {
  const { commentText } = req.body;
  const { postId } = req.params;
  const userEmail = req.session.user.email;

  if (!commentText || !userEmail) {
    return res.status(400).send('Comment text and user email are required.');
  }

  const insertSql = 'INSERT INTO comment (postid, commentdetail, email) VALUES (?, ?, ?)';
  con.query(insertSql, [postId, commentText, userEmail], (err, result) => {
    if (err) {
      console.error('Error inserting comment:', err);
      return res.status(500).send('Database error: ' + (err.sqlMessage || err.message));
    }


    const selectSql = `SELECT comment.commentdetail, student.first_name, student.last_name 
                       FROM comment  
                       JOIN student ON comment.email = student.email 
                       WHERE comment.commentid = ?`;

    con.query(selectSql, [result.insertId], (err, newCommentResults) => {
      if (err) {
        console.error('Error fetching new comment:', err);
        return res.status(500).send('Error fetching new comment');
      }

      const newComment = {
        detail: newCommentResults[0].commentdetail,
        name: `${newCommentResults[0].first_name} ${newCommentResults[0].last_name}`
      };

      res.send({ message: 'Comment added successfully', comment: newComment });
    });
  });
});




app.get('/delete-comment/:commentid', (req, res) => {
  const commentId = req.params.commentid;
  const userEmail = req.session.userEmail;


  if (userEmail !== '6431501124@lamduan.mfu.ac.th') {
    return res.status(403).send({ message: 'You are not authorized to delete this comment.' });
  }


  const getCommentQuery = `
      SELECT c.commentdetail, s.studentid
      FROM comment c
      JOIN student s ON c.email = s.email
      WHERE c.commentid = ?
  `;

  con.query(getCommentQuery, [commentId], (err, result) => {
    if (err) {
      console.error('Error fetching comment details:', err);
      return res.status(500).send({ message: 'Error fetching comment details.' });
    }

    if (result.length === 0) {
      return res.status(404).send({ message: 'Comment not found.' });
    }

    const commentDetail = result[0].commentdetail;
    const studentId = result[0].studentid;


    const deleteCommentQuery = 'DELETE FROM comment WHERE commentid = ?';

    con.query(deleteCommentQuery, [commentId], (err, deleteResult) => {
      if (err) {
        console.error('Error deleting comment:', err);
        return res.status(500).send({ message: 'Error deleting comment.' });
      }

      if (deleteResult.affectedRows === 0) {
        return res.status(404).send({ message: 'Comment not found for deletion.' });
      }

      const notificationMessage = `Your comment: "${commentDetail}" has been deleted by an admin.`;
      sendDeletionNotification(studentId, notificationMessage);


      res.render('confirmation', {
        message: `Your comment: "${commentDetail}" has been deleted by an admin.`
      });
    });
  });
});





app.post('/delete-comment/:commentid', (req, res) => {
  const commentId = req.params.commentid;
  const userEmail = req.session.user.email;

  console.log("Received commentId:", commentId);
  console.log("User email:", userEmail);


  if (userEmail !== '6431501124@lamduan.mfu.ac.th') {
    return res.status(403).send({ message: 'You are not authorized to delete this comment.' });
  }


  const getCommentQuery = `
      SELECT c.commentdetail, s.studentid
      FROM comment c
      JOIN student s ON c.email = s.email
      WHERE c.commentid = ?
  `;

  con.query(getCommentQuery, [commentId], (err, result) => {
    if (err) {
      console.error('Error fetching comment details:', err);
      return res.status(500).send({ message: 'Error fetching comment details.' });
    }

    if (result.length === 0) {
      console.log('No comment found with that ID:', commentId);
      return res.status(404).send({ message: 'Comment not found.' });
    }

    const commentDetail = result[0].commentdetail;
    const studentId = result[0].studentid;


    const deleteCommentQuery = 'DELETE FROM comment WHERE commentid = ?';

    con.query(deleteCommentQuery, [commentId], (err, deleteResult) => {
      if (err) {
        console.error('Error deleting comment:', err);
        return res.status(500).send({ message: 'Error deleting comment.' });
      }

      if (deleteResult.affectedRows === 0) {
        console.log('No comment deleted, affectedRows is 0');
        return res.status(404).send({ message: 'Comment not found for deletion.' });
      }

      console.log('Comment successfully deleted:', deleteResult);


      const notificationMessage = `Your comment: "${commentDetail}" has been deleted by an admin.`;
      sendDeletionNotification(studentId, notificationMessage);


      res.send({ message: `Comment deleted successfully.` });
    });
  });
});





app.get('/commuadmin/getPosts', (req, res) => {

  const sqlQuery = `
  SELECT 
      postt.postid, 
      postt.postdetail, 
      postt.posttime, 
      COUNT(comment.commentid) AS commentCount,
      student.first_name,
      student.last_name
  FROM postt
  LEFT JOIN comment ON postt.postid = comment.postid
  LEFT JOIN student ON postt.email = student.email
  GROUP BY postt.postid
  ORDER BY postt.posttime DESC;;
`;

  con.query(sqlQuery, (err, results) => {
    if (err) {
      console.error('Error fetching posts:', err);
      return res.status(500).json({ message: 'Failed to fetch posts.' });
    }

    res.json(results);
  });
});



app.delete('/commuadmin/delete/:postId', (req, res) => {
  const postId = req.params.postId;


  const getPostQuery = `
      SELECT s.studentid, p.postdetail 
      FROM postt p
      JOIN student s ON p.email = s.email
      WHERE p.postid = ?`;

  con.query(getPostQuery, [postId], (err, result) => {
    if (err) {
      console.error('Error fetching post:', err);
      return res.status(500).json({ message: 'Failed to fetch post information.' });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: 'Post not found.' });
    }

    const studentId = result[0].studentid;
    const postDetail = result[0].postdetail;

    const notificationMessage = `Your post with the details: "${postDetail}" has been deleted by an admin.`;
    sendDeletionNotification(studentId, notificationMessage);

    const deletePostQuery = 'DELETE FROM postt WHERE postid = ?';

    con.query(deletePostQuery, [postId], (err, result) => {
      if (err) {
        console.error('Error deleting post:', err);
        return res.status(500).json({ message: 'Failed to delete post.' });
      }

      res.json({ message: result.affectedRows > 0 ? 'Post deleted successfully.' : 'Post not found.' });
    });
  });
});




const port = 3000;
app.listen(port, function () {
  console.log("Server is ready at " + port);
});